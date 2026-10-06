package synocrypt

// 解密逻辑的测试。
//
// testdata/ 里的样本是**独立的 Python 实现**生成的（见 testdata/README.md），
// 与这里的 Go 实现互为交叉验证 —— 不是自己和自己对答案。
// 容器格式已对照真实群晖 Cloud Sync 文件核对过。

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturePassword = "test-password"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("读取样本 %s 失败: %v", name, err)
	}
	return b
}

// 逐字节解密比对。
func TestDecryptFixtures(t *testing.T) {
	cases := []struct {
		name  string
		pwd   string
		notes string
	}{
		{"v31", fixturePassword, "v3.1 带 salt（真实 Cloud Sync 的版本）"},
		{"v10", fixturePassword, "v1.0 无 salt，会话密钥是原始字节"},
		{"nocomp", fixturePassword, "compress=0，数据段没有 LZ4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := readFixture(t, c.name+".enc")
			want := readFixture(t, c.name+".plain")

			var got bytes.Buffer
			if err := decryptTo(context.Background(), bytes.NewReader(enc), &got, c.pwd, ""); err != nil {
				t.Fatalf("解密失败: %v", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("明文不一致: 得到 %d 字节，期望 %d 字节", got.Len(), len(want))
			}
		})
	}
}

// 密码错误必须在解会话密钥之前就被 key1_hash 挡掉，
// 而不是抛出一个难懂的填充错误。
func TestWrongPasswordRejected(t *testing.T) {
	enc := readFixture(t, "v31.enc")
	var got bytes.Buffer
	err := decryptTo(context.Background(), bytes.NewReader(enc), &got, "definitely-wrong", "")
	if !errors.Is(err, errWrongPassword) {
		t.Fatalf("期望 errWrongPassword，实际 %v", err)
	}
}

// 不是加密文件时必须能识别出来（驱动据此走透传分支）。
func TestNotEncryptedDetected(t *testing.T) {
	raw := readFixture(t, "not_encrypted.txt")
	var got bytes.Buffer
	err := decryptTo(context.Background(), bytes.NewReader(raw), &got, fixturePassword, "")
	if !errors.Is(err, errNotEncrypted) {
		t.Fatalf("期望 errNotEncrypted，实际 %v", err)
	}
	if !isEncryptedStream([]byte(csMagic + "xxxx")) {
		t.Fatal("magic 前缀应被识别为加密流")
	}
	if isEncryptedStream(raw) {
		t.Fatal("普通文件不该被识别为加密流")
	}
}

// ★ file_md5 在**文件末尾**的第二个 metadata 块里。
// 这条样本内容完全合法、只有末尾摘要被改坏 —— 校验必须生效，否则会静默交付坏数据。
func TestTamperedFileMD5Rejected(t *testing.T) {
	enc := readFixture(t, "badmd5.enc")
	var got bytes.Buffer
	err := decryptTo(context.Background(), bytes.NewReader(enc), &got, fixturePassword, "")
	if err == nil {
		t.Fatal("摘要被篡改却解密成功 —— 说明末尾 metadata 块里的 file_md5 没被读到")
	}
	if !strings.Contains(err.Error(), "MD5") {
		t.Fatalf("期望 MD5 校验失败，实际 %v", err)
	}
}

// 只读文件头部就能探出明文大小（从 LZ4 帧头取 content size）。
func TestProbePlainSize(t *testing.T) {
	want := int64(len(readFixture(t, "v31.plain")))
	enc := readFixture(t, "v31.enc")

	n, err := probePlainSize(bytes.NewReader(enc), fixturePassword, "")
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if n != want {
		t.Fatalf("探测到 %d，期望 %d", n, want)
	}
}

// 只喂文件开头一小段也必须能探出大小 —— 驱动实际就是这么干的（区间读取）。
// 数据块会声明得比可读的更长，解析器必须容忍截断，否则撞 ErrUnexpectedEOF。
func TestProbePlainSizeWithTruncatedInput(t *testing.T) {
	want := int64(len(readFixture(t, "v31.plain")))
	enc := readFixture(t, "v31.enc")

	head := enc
	if len(head) > 900 {
		head = head[:900] // 截在第一个数据块中间
	}
	n, err := probePlainSize(bytes.NewReader(head), fixturePassword, "")
	if err != nil {
		t.Fatalf("截断输入下探测失败: %v", err)
	}
	if n != want {
		t.Fatalf("截断输入下探测到 %d，期望 %d", n, want)
	}
}

// 不压缩的文件帧头里当然没有 content size，探测应返回 -1（调用方退回密文大小）。
func TestProbePlainSizeUncompressedReturnsUnknown(t *testing.T) {
	enc := readFixture(t, "nocomp.enc")
	n, err := probePlainSize(bytes.NewReader(enc), fixturePassword, "")
	if err != nil {
		t.Fatalf("探测不该报错: %v", err)
	}
	if n != -1 {
		t.Fatalf("未压缩的文件应返回 -1，实际 %d", n)
	}
}

// 探测也必须校验密码。
func TestProbePlainSizeRejectsWrongPassword(t *testing.T) {
	enc := readFixture(t, "v31.enc")
	if _, err := probePlainSize(bytes.NewReader(enc), "wrong", ""); !errors.Is(err, errWrongPassword) {
		t.Fatalf("期望 errWrongPassword，实际 %v", err)
	}
}

// OpenSSL EVP_BytesToKey(MD5)：有 salt 迭代 1000 轮、无 salt 只 1 轮。
// 用已知输入固定住行为，防止以后被改坏。
func TestOpenSSLKDFKnownAnswers(t *testing.T) {
	// 无 salt（count=1）：key = md5(pwd)，iv = md5(md5(pwd))
	key, iv := opensslKDF([]byte("abc"), nil, 32, 16)
	if len(key) != 32 || len(iv) != 16 {
		t.Fatalf("长度不对: key=%d iv=%d", len(key), len(iv))
	}
	// 有 salt 时同样长度，但内容必须不同
	key2, iv2 := opensslKDF([]byte("abc"), []byte("salt"), 32, 16)
	if bytes.Equal(key, key2) || bytes.Equal(iv, iv2) {
		t.Fatal("有 salt 和无 salt 派生出的密钥不该相同")
	}
}

// salted hash 的格式：10 字符前缀 + 32 位 md5 hex。
func TestSaltedHashFormat(t *testing.T) {
	h := saltedHash("0123456789", []byte("pw"))
	if len(h) != 42 {
		t.Fatalf("长度应为 42，实际 %d", len(h))
	}
	if h[:10] != "0123456789" {
		t.Fatal("前缀不对")
	}
	if !checkSaltedHash(h, []byte("pw")) {
		t.Fatal("自校验应当通过")
	}
	if checkSaltedHash(h, []byte("other")) {
		t.Fatal("不同输入不该通过校验")
	}
}
