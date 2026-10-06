package synocrypt

// 缓存键与「明文大小缓存」。
// 真正的明文缓存（边下边解）在 progressive.go。

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// cacheKey 由挂载路径 + 文件路径 + 修改时间决定。
//
// 故意**不含文件大小**：列表里报的大小可能是密文大小、也可能被明文大小缓存修正过，
// 把它放进键里会导致同一个文件算出两个键，缓存反复失效。
// 修改时间在底层文件被重新同步后会变，足够用来判失效。
func cacheKey(storage *model.Storage, obj model.Obj) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d",
		storage.MountPath, obj.GetPath(), obj.ModTime().UnixNano())
	return hex.EncodeToString(h.Sum(nil))
}

// countingWriter 统计写出的字节数。
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// ---------------------------------------------------------------- 明文大小缓存
//
// 为什么需要：目录列表里报的是**密文大小**（比明文大），而框架在
// `link.ContentLength <= 0` 时会回退用 `Obj.GetSize()`。对 0 字节的明文来说
// ContentLength 就是 0，框架于是按密文大小去读，必然 EOF 报错。
// 所以必须知道明文大小。首次解密后把真实大小记下来，之后列表就准了。
//
// 结果持久化到 <cacheDir>/sizes.json，进程重启也不丢。

type sizeCache struct {
	file string

	mu    sync.RWMutex
	m     map[string]int64
	dirty bool

	stopOnce sync.Once
	stop     chan struct{}
}

func newSizeCache(dir string) *sizeCache {
	c := &sizeCache{
		file: filepath.Join(dir, "sizes.json"),
		m:    map[string]int64{},
		stop: make(chan struct{}),
	}
	if b, err := os.ReadFile(c.file); err == nil {
		_ = json.Unmarshal(b, &c.m)
	}
	go c.flushLoop()
	return c
}

func (c *sizeCache) get(key string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n, ok := c.m[key]
	return n, ok
}

func (c *sizeCache) set(key string, n int64) {
	if n < 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.m[key]; ok && old == n {
		return
	}
	c.m[key] = n
	c.dirty = true
}

func (c *sizeCache) flushLoop() {
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

func (c *sizeCache) flush() {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	b, err := json.Marshal(c.m)
	if err == nil {
		c.dirty = false
	}
	c.mu.Unlock()
	if err != nil {
		return
	}
	tmp := c.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, c.file)
}

func (c *sizeCache) close() {
	c.stopOnce.Do(func() { close(c.stop) })
}
