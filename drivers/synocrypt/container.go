package synocrypt

// 群晖 Cloud Sync 客户端加密文件（`__CLOUDSYNC_ENC__`）的解密实现。
//
// 格式与算法完全依据开源实现 syndecrypt（marnix / anojht）反推而来，
// 该实现是群晖官方闭源工具的等价物：
//   - 容器：magic + MD5(magic) + 一串 TLV 对象（metadata 块 + 若干 data 块）
//   - 密钥派生：OpenSSL EVP_BytesToKey(MD5)，有 salt 时迭代 1000 轮
//   - 会话密钥：AES-256-CBC 解 enc_key1（或 RSA 解 enc_key2）
//   - 数据：AES-256-CBC（跨块连续），PKCS#7 填充
//   - 压缩：LZ4 frame（标准帧格式）
//   - 完整性：明文 MD5 == metadata.file_md5
//
// 注意：因为数据段是「连续 CBC + 单个 LZ4 帧」，**无法随机访问**，
// 想读文件中间某段必须从头解压。调用方（driver.go）据此采用「全量解密 + 本地缓存」。

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/pierrec/lz4/v4"
)

const (
	csMagic = "__CLOUDSYNC_ENC__"

	tDict   = 0x42
	tEnd    = 0x40
	tBytes  = 0x11
	tString = 0x10
	tInt    = 0x01
)

// errNotEncrypted 表示这个文件不是 Cloud Sync 加密文件，调用方应原样透传。
var errNotEncrypted = errors.New("not a Synology Cloud Sync encrypted file")

var errWrongPassword = errors.New("解密失败：密码或 salt 不正确")

type dict map[string]any

// ---------------------------------------------------------------- TLV 解析

type tlvReader struct {
	r *bufio.Reader
	// partial 为 true 时，长度字段声明得比实际可读的还多也不会报错，
	// 而是返回已经读到的部分。仅用于「只读文件头部」的明文大小探测。
	partial bool
}

func newTLVReader(r io.Reader) *tlvReader {
	return &tlvReader{r: bufio.NewReaderSize(r, 256*1024)}
}

// readObject 读一个 TLV 对象。terminated 为 true 表示遇到了 0x40 终止符或流结束。
func (t *tlvReader) readObject() (val any, terminated bool, err error) {
	b, err := t.r.ReadByte()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, true, nil
		}
		return nil, false, err
	}
	switch b {
	case tEnd:
		return nil, true, nil
	case tDict:
		m := dict{}
		for {
			k, end, err := t.readObject()
			if err != nil {
				return nil, false, err
			}
			if end {
				break
			}
			v, _, err := t.readObject()
			if err != nil {
				return nil, false, err
			}
			if ks, ok := k.(string); ok {
				m[ks] = v
			}
		}
		return m, false, nil
	case tBytes:
		bs, err := t.readSized()
		return bs, false, err
	case tString:
		bs, err := t.readSized()
		if err != nil {
			return nil, false, err
		}
		return string(bs), false, nil
	case tInt:
		lb, err := t.r.ReadByte()
		if err != nil {
			return nil, false, err
		}
		buf := make([]byte, lb)
		if _, err := io.ReadFull(t.r, buf); err != nil {
			return nil, false, err
		}
		var n uint64
		for _, c := range buf {
			n = n<<8 | uint64(c)
		}
		return n, false, nil
	}
	return nil, false, fmt.Errorf("未知的 TLV 类型字节 0x%02X", b)
}

// readSized 读 [2 字节大端长度][数据]
func (t *tlvReader) readSized() ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(t.r, l[:]); err != nil {
		return nil, err
	}
	n := int(l[0])<<8 | int(l[1])
	buf := make([]byte, n)
	got, err := io.ReadFull(t.r, buf)
	if err != nil {
		if t.partial && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
			return buf[:got], nil
		}
		return nil, err
	}
	return buf, nil
}

// ---------------------------------------------------------------- 元数据

type csMeta struct {
	versionMajor   int
	versionMinor   int
	salt           string
	encKey1        []byte // base64 解出，用密码解
	key1Hash       string // salted hash，可用于提前校验密码
	sessionKeyHash string
	fileName       string

	// compress / encrypt 是 0/1 开关。真实文件（v3.1）里两者都是 1。
	// 字段缺失时按 1 处理。
	compress int
	encrypt  int
}

func toInt(v any) int {
	switch x := v.(type) {
	case uint64:
		return int(x)
	case int:
		return x
	case string:
		var n int
		fmt.Sscanf(x, "%d", &n)
		return n
	}
	return 0
}

// toFlag 读 0/1 开关，字段缺失或值非法时返回 def。
func toFlag(v any, def int) int {
	if v == nil {
		return def
	}
	n := toInt(v)
	if n != 0 && n != 1 {
		return def
	}
	return n
}

func parseMeta(md dict) csMeta {
	m := csMeta{compress: 1, encrypt: 1}
	if s, ok := md["salt"].(string); ok {
		m.salt = s
	}
	if s, ok := md["file_name"].(string); ok {
		m.fileName = s
	}
	if s, ok := md["key1_hash"].(string); ok {
		m.key1Hash = s
	}
	if s, ok := md["session_key_hash"].(string); ok {
		m.sessionKeyHash = s
	}
	if s, ok := md["enc_key1"].(string); ok {
		m.encKey1 = b64decode(s)
	}
	if v, ok := md["version"].(dict); ok {
		m.versionMajor = toInt(v["major"])
		m.versionMinor = toInt(v["minor"])
	}
	m.compress = toFlag(md["compress"], 1)
	m.encrypt = toFlag(md["encrypt"], 1)
	return m
}

func b64decode(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b
	}
	return nil
}

// ---------------------------------------------------------------- 密码学

// opensslKDF 复刻 OpenSSL 的 EVP_BytesToKey(MD5)：
// 有 salt 时迭代 1000 轮，无 salt 时只迭代 1 轮。
func opensslKDF(pwd, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	count := 1
	if len(salt) > 0 {
		count = 1000
	}
	var prev []byte
	out := make([]byte, 0, keyLen+ivLen)
	for len(out) < keyLen+ivLen {
		h := md5.New()
		h.Write(prev)
		h.Write(pwd)
		h.Write(salt)
		d := h.Sum(nil)
		for i := 1; i < count; i++ {
			s := md5.Sum(d)
			d = s[:]
		}
		prev = d
		out = append(out, d...)
	}
	return out[:keyLen], out[keyLen : keyLen+ivLen]
}

func aesCBCDecryptStrip(ct, key, iv []byte) ([]byte, error) {
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度非法: %d", len(ct))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return stripPKCS7(pt)
}

func stripPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(b) {
		return nil, fmt.Errorf("PKCS#7 填充字节非法: %d", pad)
	}
	for _, c := range b[len(b)-pad:] {
		if int(c) != pad {
			return nil, errors.New("PKCS#7 填充内容不一致")
		}
	}
	return b[:len(b)-pad], nil
}

// saltedHash 复刻 syndecrypt 的 salted_hash_of：salt 前缀 + MD5(salt + data)
func saltedHash(salt string, data []byte) string {
	h := md5.New()
	h.Write([]byte(salt))
	h.Write(data)
	return salt + hex.EncodeToString(h.Sum(nil))
}

func checkSaltedHash(expect string, data []byte) bool {
	if len(expect) < 10 {
		return true // 长度不够就没法校验，放过
	}
	return saltedHash(expect[:10], data) == expect
}

// ---------------------------------------------------------------- 流式解密

// csFile 已完成头部与 metadata 解析，可继续拉取数据块。
type csFile struct {
	tr   *tlvReader
	meta csMeta
	// 数据段的 AES-CBC 状态
	block cipher.Block
	iv    []byte

	// file_md5 不在开头那个 metadata 块里——真实文件把它放在**文件末尾**
	// 第二个 metadata 块（实测 v3.1 的 IMG_0038.JPG：块 0 是密钥信息，
	// 块 43 只有 {type: metadata, file_md5: ...}）。所以要在遍历过程中
	// 随手捕获，等整个流读完再校验。pump 跑在 goroutine 里，用锁保护。
	mu      sync.Mutex
	fileMD5 string
}

func (c *csFile) setFileMD5(s string) {
	if s == "" {
		return
	}
	c.mu.Lock()
	c.fileMD5 = s
	c.mu.Unlock()
}

func (c *csFile) getFileMD5() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fileMD5
}

// openCS 解析 magic、校验 magic hash、读出 metadata 块。
func openCS(r io.Reader) (*csFile, error) {
	tr := newTLVReader(r)

	head := make([]byte, len(csMagic))
	if _, err := io.ReadFull(tr.r, head); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errNotEncrypted
		}
		return nil, err
	}
	if string(head) != csMagic {
		return nil, errNotEncrypted
	}

	mh := make([]byte, 32)
	if _, err := io.ReadFull(tr.r, mh); err != nil {
		return nil, fmt.Errorf("读取 magic hash 失败: %w", err)
	}
	want := fmt.Sprintf("%x", md5.Sum([]byte(csMagic)))
	if string(mh) != want {
		return nil, fmt.Errorf("magic hash 不匹配: 期望 %s, 实际 %s", want, string(mh))
	}

	obj, end, err := tr.readObject()
	if err != nil {
		return nil, err
	}
	if end {
		return nil, errors.New("文件在 metadata 块之前就结束了")
	}
	md, ok := obj.(dict)
	if !ok {
		return nil, errors.New("第一个块不是字典")
	}
	if t, _ := md["type"].(string); t != "metadata" {
		return nil, fmt.Errorf("第一个块的类型是 %q，期望 metadata", t)
	}

	f := &csFile{tr: tr, meta: parseMeta(md)}
	// 有些实现会把 file_md5 放在开头这块里，一并接住
	if s, ok := md["file_md5"].(string); ok {
		f.setFileMD5(s)
	}
	return f, nil
}

// setup 用密码派生出数据密钥，之后才能解密数据块。
func (c *csFile) setup(password, salt string) error {
	m := &c.meta
	if m.encrypt == 0 {
		// encrypt=0：内容没加密，只是套了容器。无需密钥。
		return nil
	}
	if len(m.encKey1) == 0 {
		return errors.New("该文件没有 enc_key1（仅用私钥加密的归档暂不支持）")
	}
	effSalt := salt
	if effSalt == "" {
		effSalt = m.salt
	}

	// 1) 密码 -> key/iv（OpenSSL KDF）
	k1, iv1 := opensslKDF([]byte(password), []byte(effSalt), 32, aes.BlockSize)

	// 2) 解出会话密钥
	sessionKey, err := aesCBCDecryptStrip(m.encKey1, k1, iv1)
	if err != nil {
		if m.key1Hash != "" && !checkSaltedHash(m.key1Hash, []byte(password)) {
			return errWrongPassword
		}
		return fmt.Errorf("解密会话密钥失败（多半是密码/salt 不对）: %w", err)
	}

	// 3) 会话密钥自检
	if m.sessionKeyHash != "" && !checkSaltedHash(m.sessionKeyHash, sessionKey) {
		return errWrongPassword
	}

	// 4) 会话密钥 -> 数据密钥
	seed := sessionKey
	if len(effSalt) > 0 {
		// 3.x 版本：会话密钥是 hex 字符串，要先转成字节
		raw, err := hex.DecodeString(string(sessionKey))
		if err != nil {
			return fmt.Errorf("会话密钥不是合法 hex: %w", err)
		}
		seed = raw
	}
	dk, div := opensslKDF(seed, nil, 32, aes.BlockSize)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}
	c.block, c.iv = block, div
	return nil
}

// pump 逐块解密并写出「已解密但仍为 LZ4 压缩」的字节流。
// 尾部 PKCS#7 填充会被剥掉（仅加密时才有）。
//
// 遍历过程中会顺手接住**末尾 metadata 块里的 file_md5**。
func (c *csFile) pump(ctx context.Context, w io.Writer) error {
	var dec *cbcStreamer
	var tw *tailWriter
	if c.meta.encrypt == 0 {
		// 没加密，直接透传，不做尾部裁剪（没有 PKCS#7 填充）
		if c.block != nil {
			return errors.New("encrypt=0 却设置了密钥，文件格式异常")
		}
	} else {
		if c.block == nil {
			return errors.New("尚未 setup")
		}
		dec = &cbcStreamer{dec: cipher.NewCBCDecrypter(c.block, c.iv)}
		tw = &tailWriter{w: w}
	}

	writeOut := func(p []byte) error {
		if len(p) == 0 {
			return nil
		}
		if tw != nil {
			_, err := tw.Write(p)
			return err
		}
		_, err := w.Write(p)
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		obj, end, err := c.tr.readObject()
		if err != nil {
			return err
		}
		if end {
			break
		}
		d, ok := obj.(dict)
		if !ok {
			continue
		}
		switch t, _ := d["type"].(string); t {
		case "metadata":
			// 末尾的 metadata 块，file_md5 在这里
			if s, ok := d["file_md5"].(string); ok {
				c.setFileMD5(s)
			}
			continue
		case "data":
		default:
			continue
		}
		raw, ok := d["data"].([]byte)
		if !ok || len(raw) == 0 {
			continue
		}
		if dec == nil {
			if err := writeOut(raw); err != nil {
				return err
			}
			continue
		}
		if err := writeOut(dec.write(raw)); err != nil {
			return err
		}
	}
	if tw != nil {
		return tw.Close()
	}
	return nil
}

// body 返回「已解密但仍为 LZ4 压缩」的流，读取方需要再套一层 lz4.NewReader。
func (c *csFile) body(ctx context.Context) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(c.pump(ctx, pw))
	}()
	return pr
}

// ---------------------------------------------------------------- 流式 CBC

// cbcStreamer 处理跨块连续的 AES-CBC：保留不足一个块的余数。
type cbcStreamer struct {
	dec cipher.BlockMode
	buf []byte
}

func (s *cbcStreamer) write(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	s.buf = append(s.buf, p...)
	n := len(s.buf) / aes.BlockSize * aes.BlockSize
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	s.dec.CryptBlocks(out, s.buf[:n])
	s.buf = append(s.buf[:0], s.buf[n:]...)
	return out
}

// tailWriter 压住最后 16 字节不写，Close 时剥掉 PKCS#7 填充再写。
type tailWriter struct {
	w    io.Writer
	tail []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.tail = append(t.tail, p...)
	if len(t.tail) <= aes.BlockSize {
		return len(p), nil
	}
	flush := len(t.tail) - aes.BlockSize
	if _, err := t.w.Write(t.tail[:flush]); err != nil {
		return 0, err
	}
	t.tail = append(t.tail[:0], t.tail[flush:]...)
	return len(p), nil
}

func (t *tailWriter) Close() error {
	if len(t.tail) == 0 {
		return nil
	}
	body, err := stripPKCS7(t.tail)
	if err != nil {
		// 填充不对时不要直接失败：LZ4 帧自带结束标记，多余的字节会被忽略。
		// 这里退化为原样写出，让上层靠 MD5 校验兜底。
		_, werr := t.w.Write(t.tail)
		return werr
	}
	_, err = t.w.Write(body)
	return err
}

// ---------------------------------------------------------------- 对外入口

// isEncryptedStream 判断流是否以 Cloud Sync magic 开头。
func isEncryptedStream(head []byte) bool {
	return bytes.HasPrefix(head, []byte(csMagic))
}

// firstChunk 只读第一个 data 块就返回，用于廉价地探测明文大小。
//
// 注意：这里**允许数据块被截断**。调用方只取了文件开头几 KB，
// 而一个数据块可能声明自己有 64KB——按常规读法会报 ErrUnexpectedEOF。
// 我们只需要它开头 16 字节，拿到就够。
func (c *csFile) firstChunk() ([]byte, error) {
	c.tr.partial = true
	defer func() { c.tr.partial = false }()

	for {
		obj, end, err := c.tr.readObject()
		if err != nil {
			return nil, err
		}
		if end {
			return nil, errors.New("文件里没有数据块")
		}
		d, ok := obj.(dict)
		if !ok {
			continue
		}
		if t, _ := d["type"].(string); t != "data" {
			continue
		}
		raw, _ := d["data"].([]byte)
		return raw, nil
	}
}

// lz4ContentSize 从 LZ4 帧头里读出原始内容大小。
//
// 帧头布局：magic(4) FLG(1) BD(1) [contentSize(8)] [dictID(4)] HC(1)
// contentSize 是可选的，由 FLG 的 bit3 决定。取不到就返回 -1。
//
// 注意：**空输入的帧不会带 contentSize**（实测 Python lz4.frame 对 b” 产出 FLG=0x60），
// 所以 0 字节文件必须靠完整解密才能确定大小。
func lz4ContentSize(b []byte) int64 {
	if len(b) < 7 {
		return -1
	}
	if b[0] != 0x04 || b[1] != 0x22 || b[2] != 0x4D || b[3] != 0x18 {
		return -1
	}
	flg := b[4]
	if flg&0x08 == 0 { // bit3：是否存了 content size
		return -1
	}
	if len(b) < 6+8 {
		return -1
	}
	var n uint64
	for i := 0; i < 8; i++ {
		n |= uint64(b[6+i]) << (8 * i) // 小端
	}
	if n > 1<<62 {
		return -1
	}
	return int64(n)
}

// probePlainSize 廉价地探测明文大小：只读文件头部，
// 解出 metadata + 第一个数据块的前 16 字节，再从 LZ4 帧头取 content size。
// 取不到（帧头没存大小、或文件本来没压缩）就返回 -1，调用方应退回密文大小。
func probePlainSize(r io.Reader, password, salt string) (int64, error) {
	c, err := openCS(r)
	if err != nil {
		return -1, err
	}
	if c.meta.compress == 0 {
		return -1, nil // 没压缩，帧头里当然没有大小
	}
	if c.meta.key1Hash != "" && !checkSaltedHash(c.meta.key1Hash, []byte(password)) {
		return -1, errWrongPassword
	}
	if err := c.setup(password, salt); err != nil {
		return -1, err
	}
	raw, err := c.firstChunk()
	if err != nil {
		return -1, err
	}
	if len(raw) < aes.BlockSize {
		return -1, nil
	}
	head := make([]byte, aes.BlockSize)
	if c.block != nil {
		cipher.NewCBCDecrypter(c.block, c.iv).CryptBlocks(head, raw[:aes.BlockSize])
	} else {
		copy(head, raw[:aes.BlockSize]) // encrypt=0
	}
	return lz4ContentSize(head), nil
}

// decryptTo 完整解密：解析容器 -> 派生密钥 -> AES-CBC -> LZ4 解压 -> 校验 MD5。
func decryptTo(ctx context.Context, r io.Reader, w io.Writer, password, salt string) error {
	c, err := openCS(r)
	if err != nil {
		return err
	}
	// 先用 key1_hash 提前把密码错误挡掉，避免报出难懂的填充错误
	if c.meta.key1Hash != "" && !checkSaltedHash(c.meta.key1Hash, []byte(password)) {
		return errWrongPassword
	}
	if err := c.setup(password, salt); err != nil {
		return err
	}

	body := c.body(ctx)
	defer body.Close()

	var src io.Reader = body
	if c.meta.compress != 0 {
		src = lz4.NewReader(body)
	}

	h := md5.New()
	if _, err := io.Copy(io.MultiWriter(w, h), src); err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}

	// file_md5 在**文件末尾**的 metadata 块里，pump 遍历时才拿到，
	// 所以必须等整个流读完再校验。
	if want := c.getFileMD5(); want != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("MD5 校验不通过: 期望 %s, 实际 %s", want, got)
		}
	}
	return nil
}
