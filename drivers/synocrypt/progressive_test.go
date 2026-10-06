package synocrypt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 造一个受控的「慢速解密」：每写一块就等一下，用来观察读取方是否真的
// 只等自己需要的那一段。
type slowFill struct {
	mu      sync.Mutex
	chunks  [][]byte
	gate    chan struct{} // 关掉才继续写下一块
	written int
}

func (s *slowFill) fill(ctx context.Context, w io.Writer) (int64, error) {
	for i, c := range s.chunks {
		if i == 1 {
			<-s.gate // 卡在第二块之前
		}
		if _, err := w.Write(c); err != nil {
			return 0, err
		}
		s.mu.Lock()
		s.written += len(c)
		s.mu.Unlock()
	}
	return 0, nil
}

func (s *slowFill) done() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written
}

func makeSlowFill(chunkSize, n int) *slowFill {
	chunks := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		chunks = append(chunks, bytes.Repeat([]byte{byte('a' + i%26)}, chunkSize))
	}
	return &slowFill{chunks: chunks, gate: make(chan struct{})}
}

func (s *slowFill) total() int64 {
	var n int64
	for _, c := range s.chunks {
		n += int64(len(c))
	}
	return n
}

// 核心测试：读取方只等自己需要的那一段，不等整个文件解完。
func TestProgressiveOnlyWaitsForNeededRange(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)
	defer c.close()

	sf := makeSlowFill(64*1024, 16) // 16 块 × 64KB = 1MB
	total := sf.total()

	pf, started, err := c.getOrStart("k1", total, sf.fill)
	if err != nil || !started {
		t.Fatalf("getOrStart: started=%v err=%v", started, err)
	}

	// 第一块已经写进去了（pump 卡在第二块之前），所以读开头应当立刻成功
	rc, err := pf.openRange(context.Background(), 0, 1024)
	if err != nil {
		t.Fatalf("读开头应该立刻成功，却报错: %v", err)
	}
	got := make([]byte, 1024)
	if _, err := io.ReadFull(rc, got); err != nil {
		t.Fatalf("读开头失败: %v", err)
	}
	_ = rc.Close()
	if !bytes.Equal(got, sf.chunks[0][:1024]) {
		t.Fatal("读到的内容和预期不一致")
	}
	if sf.done() != 64*1024 {
		t.Fatalf("此时应该只写了 1 块，实际 %d", sf.done())
	}

	// 读末尾：pump 还卡着，必须阻塞
	blocked := make(chan error, 1)
	go func() {
		rc, e := pf.openRange(context.Background(), total-100, 100)
		if e == nil {
			_ = rc.Close()
		}
		blocked <- e
	}()
	select {
	case e := <-blocked:
		t.Fatalf("读末尾不该在解密未推进时就成功（err=%v）", e)
	case <-time.After(200 * time.Millisecond):
		// 正确：还在等
	}

	// 放行，读末尾应当完成
	close(sf.gate)
	select {
	case e := <-blocked:
		if e != nil {
			t.Fatalf("放行后读末尾仍失败: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("放行后读末尾超时")
	}

	if pf.knownTotal() != total {
		t.Fatalf("总大小 %d，预期 %d", pf.knownTotal(), total)
	}
}

// 同一文件重复 getOrStart 必须复用同一个解密任务，而不是重跑一遍。
func TestProgressiveReusesPump(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)
	defer c.close()

	sf := makeSlowFill(1024, 4)
	close(sf.gate) // 不阻塞，让它跑完

	pf1, started1, err := c.getOrStart("k2", sf.total(), sf.fill)
	if err != nil || !started1 {
		t.Fatalf("第一次应当启动任务: started=%v err=%v", started1, err)
	}
	if _, err := pf1.waitDone(context.Background()); err != nil {
		t.Fatal(err)
	}

	pf2, started2, err := c.getOrStart("k2", sf.total(), sf.fill)
	if err != nil {
		t.Fatal(err)
	}
	if started2 {
		t.Fatal("第二次不该再启动一个新任务")
	}
	if pf1 != pf2 {
		t.Fatal("第二次应当返回同一个 progressiveFile")
	}
}

// 解密失败时，读取方必须拿到错误，而不是挂住或读到垃圾。
func TestProgressivePropagatesError(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)
	defer c.close()

	boom := errors.New("模拟解密失败")
	fill := func(ctx context.Context, w io.Writer) (int64, error) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
		return 0, boom
	}

	pf, _, err := c.getOrStart("k3", 100000, fill)
	if err != nil {
		t.Fatal(err)
	}

	// 等它失败
	deadline := time.Now().Add(5 * time.Second)
	for pf.knownTotal() >= 0 || time.Now().Before(deadline) {
		if _, e := pf.waitDone(context.Background()); e != nil {
			if !errors.Is(e, boom) {
				t.Fatalf("错误应被透传，实际 %v", e)
			}
			break
		}
		break
	}

	// 读超出已解出的部分必须报错，而不是静默返回短数据
	rc, err := pf.openRange(context.Background(), 90000, 100)
	if err == nil {
		_ = rc.Close()
		t.Fatal("解失败后读取应当报错")
	}
}

// 取消 context 时，等待中的读取必须尽快返回。
func TestProgressiveRespectsContextCancel(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)
	defer c.close()

	sf := makeSlowFill(1024, 8) // 会卡住
	pf, _, err := c.getOrStart("k4", sf.total(), sf.fill)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err = pf.openRange(ctx, sf.total()-10, 10)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("期望 context.Canceled，实际 %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("取消响应太慢: %v", d)
	}
	close(sf.gate)
}

// 并发读多个区间，内容都要正确（顺带跑 -race）。
func TestProgressiveConcurrentRanges(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)
	defer c.close()

	const chunk = 32 * 1024
	const n = 12
	sf := makeSlowFill(chunk, n)
	close(sf.gate)

	pf, _, err := c.getOrStart("k5", sf.total(), sf.fill)
	if err != nil {
		t.Fatal(err)
	}

	var want []byte
	for _, ch := range sf.chunks {
		want = append(want, ch...)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := int64((i * 4096) % len(want))
			length := int64(8192)
			if start+length > int64(len(want)) {
				length = int64(len(want)) - start
			}
			rc, e := pf.openRange(context.Background(), start, length)
			if e != nil {
				errs <- e
				return
			}
			defer rc.Close()
			got, e := io.ReadAll(rc)
			if e != nil {
				errs <- e
				return
			}
			if !bytes.Equal(got, want[start:start+length]) {
				errs <- errors.New("并发读到的内容不一致")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// 后台解密拿到的必须是**缓存的生命周期 context**，不是某个请求的 ——
// 客户端断开不该中断正在为其他读者填的缓存。close() 时才取消。
func TestPumpUsesCacheContextNotRequestContext(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)

	got := make(chan context.Context, 1)
	fill := func(ctx context.Context, w io.Writer) (int64, error) {
		got <- ctx
		return 0, nil
	}
	if _, _, err := c.getOrStart("k7", 100, fill); err != nil {
		t.Fatal(err)
	}

	ctx := <-got
	select {
	case <-ctx.Done():
		t.Fatal("close 之前不该被取消")
	default:
	}

	c.close()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("close 之后传给 fill 的 ctx 必须被取消")
	}
}

// close() 必须等在跑的解密退出：它们持有缓存文件的句柄，
// 不退出的话在 Windows 上目录都删不掉（TempDir 清理就是这么失败的）。
func TestCloseWaitsForRunningPumps(t *testing.T) {
	dir := t.TempDir()
	c := newDecryptCache(dir, 1<<30, time.Hour)

	started := make(chan struct{})
	exited := make(chan struct{})
	fill := func(ctx context.Context, w io.Writer) (int64, error) {
		close(started)
		defer close(exited)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(30 * time.Second):
			return 0, nil
		}
	}
	if _, _, err := c.getOrStart("k8", 100, fill); err != nil {
		t.Fatal(err)
	}
	<-started

	t0 := time.Now()
	c.close()
	elapsed := time.Since(t0)

	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("close 返回时解密协程应当已经退出")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("close 应当靠 ctx 取消立刻返回，实际等了 %v", elapsed)
	}
}

// 启动时清理：manifest 里没有的 .plain 必须被删掉（上次跑挂了留下的半成品）。
func TestProgressiveSweepRemovesOrphans(t *testing.T) {
	dir := t.TempDir()

	// 先正常跑完一个，写入 manifest
	c1 := newDecryptCache(dir, 1<<30, time.Hour)
	sf := makeSlowFill(1024, 2)
	close(sf.gate)
	if _, _, err := c1.getOrStart("good", sf.total(), sf.fill); err != nil {
		t.Fatal(err)
	}
	pf, _, _ := c1.getOrStart("good", sf.total(), sf.fill)
	if _, err := pf.waitDone(context.Background()); err != nil {
		t.Fatal(err)
	}
	c1.flush()
	c1.close()

	// 再手工放一个孤儿文件
	if err := os.WriteFile(filepath.Join(dir, "orphan.plain"), []byte("half done"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 重新打开缓存，孤儿应被清掉，正常的应保留
	c2 := newDecryptCache(dir, 1<<30, time.Hour)
	defer c2.close()

	if _, err := os.Stat(filepath.Join(dir, "orphan.plain")); err == nil {
		t.Fatal("manifest 里没有的半成品应当被删掉")
	}
	if _, err := os.Stat(filepath.Join(dir, "good.plain")); err != nil {
		t.Fatalf("已完成的缓存不该被删掉: %v", err)
	}
}
