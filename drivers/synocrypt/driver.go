package synocrypt

// SynoCrypt：把群晖 Cloud Sync 加密备份「实时解密」后挂载出来。
//
// 定位是「叠加型驱动」——它自己不去访问网盘，而是引用本实例里已经挂好的
// 另一个存储（remote_path），在读取时把明文还原出来。同类驱动：Crypt / Alias / Strm。
//
// 结构上照抄 drivers/crypt：
//   - GetRootPath() 声明实际根目录落在底层挂载的哪里
//   - List 委托给 fs.List（本格式文件名是明文的，所以列表可以直接透传）
//   - Link 返回 RangeReader 而不是 URL
//
// 读取是**边下载边解密**的：解密在后台顺序推进并落盘，读取方只等自己需要的那一段
// （见 progressive.go）。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	stdpath "path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// probeReadBytes 探测明文大小时只读文件开头这么多字节。
// 实测真实文件（v3.1）的 metadata 块是 799 字节，加上第一个数据块的 TLV 头
// 与 16 字节密文，4096 有 5 倍余量。
const probeReadBytes = 4096

// smallFileProbeLimit 密文小于这个大小的文件，无论是否开启 probe_size 都去探一下。
// 这类文件本身极小，代价可忽略，而 0 字节文件恰好落在这个区间里——
// 不探的话列表会报密文大小，框架按密文大小去读 0 字节的明文必然 EOF 报错。
const smallFileProbeLimit = 8192

// probeConcurrency 探测明文大小时的并发上限，避免把网盘 API 打爆。
const probeConcurrency = 4

type SynoCrypt struct {
	model.Storage
	Addition
	cache  *decryptCache
	sizes  *sizeCache
	probed sync.Map // 探测失败的文件记下来，避免每次列表都重试
}

// probeItem 是列表里待探测明文大小的一个文件。
type probeItem struct {
	obj     *model.Object
	key     string
	encSize int64
}

func (d *SynoCrypt) Config() driver.Config {
	return config
}

func (d *SynoCrypt) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *SynoCrypt) Init(ctx context.Context) error {
	d.RemotePath = utils.FixAndCleanPath(d.RemotePath)
	if d.RemotePath == "/" || d.RemotePath == "" {
		return errors.New("remote_path 不能为空，请填密文所在的挂载路径")
	}
	if strings.TrimSpace(d.Password) == "" {
		return errors.New("password 不能为空")
	}

	dir := strings.TrimSpace(d.CacheDir)
	if dir == "" {
		dir = filepath.Join("data", "temp", "synocrypt")
	}
	if !filepath.IsAbs(dir) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return fmt.Errorf("解析缓存目录失败: %w", err)
		}
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建缓存目录 %s 失败: %w", dir, err)
	}

	maxSize := int64(d.CacheMaxMB) << 20
	if maxSize <= 0 {
		maxSize = 8 << 30
	}
	ttl := time.Duration(d.CacheTTLMin) * time.Minute

	d.cache = newDecryptCache(dir, maxSize, ttl)
	d.sizes = newSizeCache(dir)
	return nil
}

func (d *SynoCrypt) Drop(ctx context.Context) error {
	if d.cache != nil {
		d.cache.close()
	}
	if d.sizes != nil {
		d.sizes.close()
	}
	return nil
}

// List 委托给底层目录。
//
// Cloud Sync 加密只加密文件内容，文件名和目录结构都是明文，所以这里不需要做任何解密。
// 唯一要做的是把**明文大小**报出去——列表里报密文大小的话，0 字节文件会让框架读错长度。
func (d *SynoCrypt) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	remoteFullPath := dir.GetPath()
	objs, err := fs.List(ctx, remoteFullPath, &fs.ListArgs{NoLog: true, Refresh: args.Refresh})
	if err != nil {
		return nil, err
	}

	var toProbe []probeItem

	result := make([]model.Obj, 0, len(objs))
	for _, obj := range objs {
		name := obj.GetName()
		if !d.ShowHidden && strings.HasPrefix(name, ".") {
			continue
		}
		mo := &model.Object{
			Path:     stdpath.Join(remoteFullPath, name),
			Name:     name,
			Size:     obj.GetSize(), // 先按密文大小，下面尽量修正
			Modified: obj.ModTime(),
			Ctime:    obj.CreateTime(),
			IsFolder: obj.IsDir(),
			Mask:     model.GetObjMask(obj) &^ model.Temp,
		}
		if !mo.IsFolder {
			key := cacheKey(d.GetStorage(), mo)
			if n, ok := d.sizes.get(key); ok {
				mo.Size = n
			} else if d.shouldProbe(key, mo.Size) {
				toProbe = append(toProbe, probeItem{obj: mo, key: key, encSize: mo.Size})
			}
		}
		result = append(result, mo)
	}

	if len(toProbe) > 0 {
		d.probeSizes(ctx, toProbe)
	}
	return result, nil
}

// shouldProbe 决定要不要为这个文件探一次明文大小。
func (d *SynoCrypt) shouldProbe(key string, encSize int64) bool {
	if _, failed := d.probed.Load(key); failed {
		return false // 探过且没探出来，别再浪费请求
	}
	return d.ProbeSize || encSize < smallFileProbeLimit
}

func (d *SynoCrypt) probeSizes(ctx context.Context, items []probeItem) {
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it probeItem) {
			defer wg.Done()
			defer func() { <-sem }()
			n, err := d.probeOne(ctx, it.obj, it.encSize)
			if err != nil || n < 0 {
				d.probed.Store(it.key, struct{}{})
				return
			}
			d.sizes.set(it.key, n)
			it.obj.Size = n
		}(it)
	}
	wg.Wait()
}

// probeOne 想办法拿到明文大小：
//  1. 先试最便宜的路子——只读文件头部，从 LZ4 帧头里取 content size
//  2. 帧头没存大小（空文件就是这样）且文件很小 → 干脆完整解密数一遍
func (d *SynoCrypt) probeOne(ctx context.Context, obj model.Obj, encSize int64) (int64, error) {
	n, err := d.probeByHeader(ctx, obj)
	if err == nil && n >= 0 {
		return n, nil
	}
	if encSize < smallFileProbeLimit {
		return d.countPlainSize(ctx, obj)
	}
	return -1, err
}

// probeByHeader 只读文件开头一小段，从 LZ4 帧头取明文大小。取不到返回 -1。
func (d *SynoCrypt) probeByHeader(ctx context.Context, obj model.Obj) (int64, error) {
	rc, err := d.openRange(ctx, obj, probeReadBytes)
	if err != nil {
		return -1, err
	}
	defer rc.Close()
	return probePlainSize(rc, d.Password, d.Salt)
}

// countPlainSize 完整解密一遍但不落盘，只为数出明文大小。仅用于小文件。
func (d *SynoCrypt) countPlainSize(ctx context.Context, obj model.Obj) (int64, error) {
	rc, err := d.openRange(ctx, obj, -1)
	if err != nil {
		return -1, err
	}
	defer rc.Close()
	cw := &countingWriter{w: io.Discard}
	if err := decryptTo(ctx, rc, cw, d.Password, d.Salt); err != nil {
		return -1, err
	}
	return cw.n, nil
}

// openRange 打开底层文件的指定区间。length < 0 表示读到结尾。
func (d *SynoCrypt) openRange(ctx context.Context, obj model.Obj, length int64) (io.ReadCloser, error) {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(obj.GetPath())
	if err != nil {
		return nil, err
	}
	remoteLink, remoteFile, err := op.Link(ctx, remoteStorage, remoteActualPath, model.LinkArgs{})
	if err != nil {
		return nil, err
	}
	size := remoteLink.ContentLength
	if size <= 0 {
		size = remoteFile.GetSize()
	}
	rrf, err := stream.GetRangeReaderFromLink(size, remoteLink)
	if err != nil {
		_ = remoteLink.Close()
		return nil, err
	}
	rc, err := rrf.RangeRead(ctx, http_range.Range{Start: 0, Length: length})
	if err != nil {
		_ = remoteLink.Close()
		return nil, err
	}
	return utils.NewReadCloser(rc, func() error {
		_ = rc.Close()
		return remoteLink.Close()
	}), nil
}

func (d *SynoCrypt) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(file.GetPath())
	if err != nil {
		return nil, err
	}
	remoteLink, remoteFile, err := op.Link(ctx, remoteStorage, remoteActualPath, model.LinkArgs{})
	if err != nil {
		return nil, err
	}

	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = remoteFile.GetSize()
	}
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		_ = remoteLink.Close()
		return nil, fmt.Errorf("底层存储不支持按区间读取，无法叠加解密层: %w", err)
	}

	// 先探一下是不是 Cloud Sync 加密文件。不是的话（比如同一目录里混了
	// @SynologyCloudSync/cloudsync_encrypt.info、缩略图、或本来就没加密的文件）
	// 就直接把底层链接原样返回，不做任何处理。
	encrypted, err := probeEncrypted(ctx, rrf)
	if err != nil {
		_ = remoteLink.Close()
		return nil, err
	}
	if !encrypted {
		return remoteLink, nil
	}

	key := cacheKey(d.GetStorage(), file)

	// 明文总大小：先查缓存，再探一次 LZ4 帧头。
	// 都拿不到就传 -1，由 progressive 那边等全量解完再定。
	total := int64(-1)
	if n, ok := d.sizes.get(key); ok {
		total = n
	} else if n, perr := d.probeByHeader(ctx, file); perr == nil && n >= 0 {
		total = n
		d.sizes.set(key, n)
	}

	// 注意 fill 用的是**缓存的生命周期 context**（pctx），不是这次请求的 ctx：
	// 客户端断开不该中断正在为其他读者填的缓存。存储被停用时由 Drop 取消。
	pf, started, err := d.cache.getOrStart(key, total, func(pctx context.Context, w io.Writer) (int64, error) {
		// remoteLink 要活到解密跑完
		defer remoteLink.Close()
		rc, rerr := rrf.RangeRead(pctx, http_range.Range{Start: 0, Length: -1})
		if rerr != nil {
			return 0, rerr
		}
		defer rc.Close()
		if derr := decryptTo(pctx, rc, w, d.Password, d.Salt); derr != nil {
			return 0, fmt.Errorf("解密 %s 失败: %w", file.GetName(), derr)
		}
		return 0, nil
	})
	if err != nil {
		_ = remoteLink.Close()
		return nil, err
	}
	if !started {
		// 复用已有的解密任务，这次拿到的底层链接没用上，直接关掉
		_ = remoteLink.Close()
	}

	// 总大小未知时退回「等全量解完」——只有这样才能给出正确的 ContentLength
	if pf.knownTotal() < 0 {
		n, werr := pf.waitDone(ctx)
		if werr != nil {
			return nil, werr
		}
		pf.setTotal(n)
	}
	size := pf.knownTotal()
	if size < 0 {
		return nil, errors.New("无法确定明文大小")
	}
	d.sizes.set(key, size) // 记下真实大小，之后目录列表就准了

	return &model.Link{
		RangeReader: stream.RangeReaderFunc(func(ctx context.Context, r http_range.Range) (io.ReadCloser, error) {
			return pf.openRange(ctx, r.Start, r.Length)
		}),
		ContentLength: size,
	}, nil
}

// probeEncrypted 读文件头部，判断是不是 Cloud Sync 加密文件。
func probeEncrypted(ctx context.Context, rrf model.RangeReaderIF) (bool, error) {
	rc, err := rrf.RangeRead(ctx, http_range.Range{Start: 0, Length: int64(len(csMagic))})
	if err != nil {
		return false, err
	}
	defer rc.Close()
	buf := make([]byte, len(csMagic))
	if _, err := io.ReadFull(rc, buf); err != nil {
		// 读不满这么长，肯定不是加密文件（空文件/极小文件）
		return false, nil
	}
	return isEncryptedStream(buf), nil
}

var _ driver.Driver = (*SynoCrypt)(nil)
