package synocrypt

// 边下载边解密（progressive）。
//
// 背景：这个格式是「跨块连续的 AES-CBC + 一整条 LZ4 流」，没有分块索引，
// 所以**明文第 N 字节之前的密文必须先解压过**，做不到真正的随机访问。
//
// 如果等整个文件解完再提供读取（最朴素的做法），放一个 4GB 的视频就得先等
// 4GB 全部下载+解密完才出画面 —— 不可接受。
//
// 这里的做法：解密在后台 goroutine 里**顺序推进并落盘**，读取方只等待
// 「自己需要的那一段」被解出来，而不是等整个文件。
// 于是：
//   - 从头播放：解出几 MB 就能出画面（边下边播）
//   - 向后拖：已经解过的部分立即返回
//   - 向前拖：等解密游标追上目标偏移（受限于下载速度，这是格式决定的硬边界）
//   - 全部解完后：等同于本地文件，任意跳转都是即时
//
// 缓存键包含底层文件的修改时间，底层一变（重新同步过）缓存自动失效。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// errCacheClosed 缓存条目被淘汰/关闭后，进行中的读取会拿到这个错误。
var errCacheClosed = errors.New("synocrypt: 缓存条目已失效")

// progressiveFile 是一个正在（或已经）解密到本地的文件。
// 所有方法都并发安全。
type progressiveFile struct {
	key  string
	path string
	f    *os.File // 只由 pump 写

	mu     sync.Mutex
	total  int64 // 明文总大小；-1 表示还不知道
	have   int64 // 已解密落盘的字节数
	done   bool
	err    error
	notify chan struct{} // 每次进度更新时关闭并重建，用于唤醒等待者
	refs   int           // 正在被读取的引用数
	usedAt time.Time

	// 解密失败（比如 MD5 对不上）后置位。
	// 读取方每次 Read 都检查它 —— 这样**正在传输中**的响应会被中断，
	// 下载工具能立刻发现，而不是拿到一份"看起来完整"的坏数据。
	broken atomic.Bool
}

func newProgressiveFile(key, path string, f *os.File, total int64) *progressiveFile {
	return &progressiveFile{
		key:    key,
		path:   path,
		f:      f,
		total:  total,
		notify: make(chan struct{}),
		usedAt: time.Now(),
	}
}

// setTotal 在探测出总大小时调用（可能晚于创建）。
func (p *progressiveFile) setTotal(n int64) {
	if n < 0 {
		return
	}
	p.mu.Lock()
	p.total = n
	p.mu.Unlock()
}

// knownTotal 返回已知的明文总大小，未知时返回 -1。
func (p *progressiveFile) knownTotal() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total
}

// addHave 推进进度并唤醒所有等待者。
func (p *progressiveFile) addHave(n int64) {
	if n <= 0 {
		return
	}
	p.mu.Lock()
	p.have += n
	p.wakeLocked()
	p.mu.Unlock()
}

func (p *progressiveFile) wakeLocked() {
	close(p.notify)
	p.notify = make(chan struct{})
}

// finish 结束解密。err 为 nil 表示正常解完。
func (p *progressiveFile) finish(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
	}
	p.done = true
	if err != nil {
		p.broken.Store(true)
	}
	if err == nil && p.total < 0 {
		p.total = p.have // 之前没探到大小，现在知道了
	}
	p.wakeLocked()
}

// fileErr 解密失败时返回错误，否则 nil。
func (p *progressiveFile) fileErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// waitFor 阻塞直到已解密字节数 >= need，或出错/结束/取消。
func (p *progressiveFile) waitFor(ctx context.Context, need int64) error {
	for {
		p.mu.Lock()
		err, have, done := p.err, p.have, p.done
		ch := p.notify
		p.mu.Unlock()

		if err != nil {
			return err
		}
		if have >= need {
			return nil
		}
		if done {
			// 解完了却还是不够，说明底层数据被截断了
			return fmt.Errorf("解密数据不足：需要 %d 字节，只有 %d 字节", need, have)
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// waitDone 等整个文件解完，返回最终大小。用于「探不到明文大小时」的兜底。
func (p *progressiveFile) waitDone(ctx context.Context) (int64, error) {
	for {
		p.mu.Lock()
		err, done, have := p.err, p.done, p.have
		ch := p.notify
		p.mu.Unlock()

		if err != nil {
			return 0, err
		}
		if done {
			return have, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// openRange 打开明文的 [start, start+length)。length < 0 表示到结尾。
//
// 关键：这里**只等自己需要的那一段**解出来，不等整个文件。
func (p *progressiveFile) openRange(ctx context.Context, start, length int64) (io.ReadCloser, error) {
	p.mu.Lock()
	total := p.total
	p.refs++
	p.usedAt = time.Now()
	p.mu.Unlock()
	defer p.release()

	if start < 0 {
		start = 0
	}
	if total >= 0 {
		if start > total {
			start = total
		}
		if length < 0 || start+length > total {
			length = total - start
		}
	}
	if length < 0 {
		length = 0
	}

	if length > 0 {
		if err := p.waitFor(ctx, start+length); err != nil {
			return nil, err
		}
	}

	f, err := os.Open(p.path)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return utils.NewReadCloser(io.LimitReader(f, 0), f.Close), nil
	}
	sr := io.NewSectionReader(f, start, length)
	return utils.NewReadCloser(&brokenAwareReader{r: sr, p: p}, f.Close), nil
}

// brokenAwareReader 在每次读取时检查解密是否已失败。
// 失败就把错误抛出去，让正在进行的响应中断 —— 避免"静默交付坏数据"。
type brokenAwareReader struct {
	r io.Reader
	p *progressiveFile
}

func (b *brokenAwareReader) Read(p []byte) (int, error) {
	if b.p.broken.Load() {
		return 0, b.p.fileErr()
	}
	return b.r.Read(p)
}

func (p *progressiveFile) release() {
	p.mu.Lock()
	p.refs--
	p.usedAt = time.Now()
	p.mu.Unlock()
}

// idle 是否可以安全淘汰：已解完且没有正在读的人。
func (p *progressiveFile) idle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done && p.refs <= 0
}

func (p *progressiveFile) size() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.have
}

// ---------------------------------------------------------------- 缓存管理

// decryptCache 管理所有 progressiveFile。
type decryptCache struct {
	dir     string
	maxSize int64
	ttl     time.Duration

	mu      sync.Mutex
	entries map[string]*progressiveFile
	locks   map[string]*sync.Mutex
	failed  map[string]error // 解密失败过的文件：后续请求直接失败，不再重试
	total   int64

	manifest map[string]int64 // key -> 已解完的大小
	dirty    bool
	stopOnce sync.Once
	stop     chan struct{}
	stopped  bool

	// 缓存的生命周期 context。后台解密用它，**不用请求的 context** ——
	// 请求会随客户端断开而取消，但解密应该继续为后续读者填缓存。
	// 只有 close()（存储被停用/删除）才取消它。
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // 追踪在跑的解密协程，close 时要等它们退出
}

// fillFunc 把明文顺序写进 writer。ctx 是缓存的生命周期 context。
type fillFunc func(ctx context.Context, w io.Writer) (int64, error)

func newDecryptCache(dir string, maxSize int64, ttl time.Duration) *decryptCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &decryptCache{
		dir:      dir,
		maxSize:  maxSize,
		ttl:      ttl,
		entries:  map[string]*progressiveFile{},
		locks:    map[string]*sync.Mutex{},
		failed:   map[string]error{},
		manifest: map[string]int64{},
		stop:     make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}
	c.loadManifest()
	c.sweep()
	go c.flushLoop()
	return c
}

func (c *decryptCache) pathFor(key string) string {
	return filepath.Join(c.dir, key+".plain")
}

func (c *decryptCache) manifestPath() string {
	return filepath.Join(c.dir, "manifest.json")
}

// getOrStart 拿到（或启动）某个文件的解密。total < 0 表示还不知道总大小。
// started 为 true 表示这次调用启动了新的解密任务（fill 会被调用）。
func (c *decryptCache) getOrStart(key string, total int64, fill fillFunc) (p *progressiveFile, started bool, err error) {

	// 同一文件只跑一次解密
	unlock := c.keyedLock(key)
	defer unlock()

	c.mu.Lock()
	if err, bad := c.failed[key]; bad {
		// 这个文件之前解密失败过，别再浪费一次下载
		c.mu.Unlock()
		return nil, false, err
	}
	if p, ok := c.entries[key]; ok {
		if _, statErr := os.Stat(p.path); statErr == nil {
			// 文件还在：如果这次探测到了大小而之前没有，补上
			if total >= 0 && p.knownTotal() < 0 {
				p.setTotal(total)
			}
			c.mu.Unlock()
			return p, false, nil
		}
		// 文件没了，丢掉重来
		c.dropLocked(key, p)
	}
	if c.stopped {
		c.mu.Unlock()
		return nil, false, errCacheClosed
	}
	c.mu.Unlock()

	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return nil, false, err
	}
	f, err := os.Create(c.pathFor(key))
	if err != nil {
		return nil, false, err
	}
	p = newProgressiveFile(key, c.pathFor(key), f, total)

	c.mu.Lock()
	c.entries[key] = p
	c.wg.Add(1)
	c.mu.Unlock()

	go c.pump(p, fill)
	return p, true, nil
}

// pump 后台顺序解密，边解边落盘，边通知等待者。
//
// 用的是**缓存的生命周期 context**，不是某个请求的 —— 客户端断开不该中断
// 正在为其他读者填的缓存。存储被停用时 close() 会取消它。
func (c *decryptCache) pump(p *progressiveFile, fill fillFunc) {
	defer c.wg.Done()

	_, err := fill(c.ctx, &progressWriter{p: p, f: p.f})
	_ = p.f.Close()

	if err == nil && p.knownTotal() >= 0 && p.size() != p.knownTotal() {
		err = fmt.Errorf("解密长度与预期不符：得到 %d 字节，预期 %d 字节", p.size(), p.knownTotal())
	}
	p.finish(err)

	if err == nil {
		c.mu.Lock()
		c.manifest[p.key] = p.size()
		c.dirty = true
		c.total += p.size()
		c.evictLocked()
		c.mu.Unlock()
	} else {
		// 解失败就把残留删掉，别让坏数据留在盘上；同时记住这个文件是坏的
		c.mu.Lock()
		if !errors.Is(err, context.Canceled) {
			// 被 close() 取消不算"文件坏了"，下次还要能重试
			c.failed[p.key] = err
		}
		c.dropLocked(p.key, p)
		c.mu.Unlock()
	}
}

// progressWriter 把解密输出写进缓存文件，并实时推进进度。
type progressWriter struct {
	p *progressiveFile
	f *os.File
}

func (w *progressWriter) Write(b []byte) (int, error) {
	n, err := w.f.Write(b)
	if n > 0 {
		w.p.addHave(int64(n))
	}
	return n, err
}

// keyedLock 保证同一个文件的解密只启动一次。
func (c *decryptCache) keyedLock(key string) func() {
	c.mu.Lock()
	mu, ok := c.locks[key]
	if !ok {
		mu = &sync.Mutex{}
		c.locks[key] = mu
	}
	c.mu.Unlock()
	mu.Lock()
	return mu.Unlock
}

func (c *decryptCache) dropLocked(key string, p *progressiveFile) {
	delete(c.entries, key)
	delete(c.manifest, key)
	c.dirty = true
	_ = os.Remove(p.path)
}

// evictLocked 超限时按最久未使用淘汰（只淘汰已解完且没人读的）。
func (c *decryptCache) evictLocked() {
	if c.maxSize <= 0 {
		return
	}
	live := int64(0)
	type kv struct {
		key string
		p   *progressiveFile
	}
	var cands []kv
	for k, p := range c.entries {
		live += p.size()
		if p.idle() {
			cands = append(cands, kv{k, p})
		}
	}
	if live <= c.maxSize {
		return
	}
	sort.Slice(cands, func(i, j int) bool {
		cands[i].p.mu.Lock()
		ui := cands[i].p.usedAt
		cands[i].p.mu.Unlock()
		cands[j].p.mu.Lock()
		uj := cands[j].p.usedAt
		cands[j].p.mu.Unlock()
		return ui.Before(uj)
	})
	for _, it := range cands {
		if live <= c.maxSize {
			break
		}
		live -= it.p.size()
		c.dropLocked(it.key, it.p)
	}
}

// ---------------------------------------------------------------- 启动清理与持久化

// sweep 启动时清理：删掉所有不在 manifest 里的 .plain（上次跑挂了留下的半成品），
// 以及超过 TTL 的已完成缓存。
func (c *decryptCache) sweep() {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	now := time.Now()
	kept := map[string]int64{}
	for _, de := range entries {
		name := de.Name()
		info, err := de.Info()
		if err != nil {
			continue
		}
		if filepath.Ext(name) == ".part" {
			_ = os.Remove(filepath.Join(c.dir, name)) // 老版本留下的临时文件
			continue
		}
		if filepath.Ext(name) != ".plain" {
			continue
		}
		key := name[:len(name)-len(".plain")]
		size, ok := c.manifest[key]
		if !ok {
			// manifest 里没有 → 上次没解完就退出了，删掉重来
			_ = os.Remove(filepath.Join(c.dir, name))
			continue
		}
		if c.ttl > 0 && now.Sub(info.ModTime()) > c.ttl {
			_ = os.Remove(filepath.Join(c.dir, name))
			continue
		}
		kept[key] = size
	}
	c.mu.Lock()
	c.manifest = kept
	c.total = 0
	for _, s := range kept {
		c.total += s
	}
	c.mu.Unlock()
}

func (c *decryptCache) loadManifest() {
	b, err := os.ReadFile(c.manifestPath())
	if err != nil {
		return
	}
	m := map[string]int64{}
	if json.Unmarshal(b, &m) == nil {
		c.manifest = m
	}
}

func (c *decryptCache) flushLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			c.flush()
			return
		case <-t.C:
			c.flush()
		}
	}
}

func (c *decryptCache) flush() {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	b, err := json.Marshal(c.manifest)
	if err == nil {
		c.dirty = false
	}
	c.mu.Unlock()
	if err != nil {
		return
	}
	tmp := c.manifestPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, c.manifestPath())
}

// close 关闭缓存：停掉后台任务、等它们退出、落盘 manifest。
//
// 必须等解密协程退出 —— 否则它们还持有缓存文件的句柄，
// 在 Windows 上会让目录删不掉（测试里的 TempDir 清理就是这么失败的）。
func (c *decryptCache) close() {
	c.mu.Lock()
	c.stopped = true
	c.mu.Unlock()

	c.cancel() // 通知所有在跑的解密停下
	c.stopOnce.Do(func() { close(c.stop) })

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// 底层驱动不响应取消时不能把 Drop 卡死，最多等 5 秒
	}
	c.flush()
}

// stats 给日志/排错用。
func (c *decryptCache) stats() (files int, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.total
}
