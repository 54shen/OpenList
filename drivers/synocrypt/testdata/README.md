# testdata

`drivers/synocrypt` 的测试样本。

## 这些文件是什么

群晖 Cloud Sync 客户端加密（`__CLOUDSYNC_ENC__`）格式的小样本，用于验证
`container.go` 里的解密实现。每个 `.enc` 配一个 `.plain`，后者是它解密后应当得到的明文。

| 文件 | 说明 |
|---|---|
| `v31.enc` / `v31.plain` | **v3.1**，带 salt（真实 Cloud Sync 用的就是这个版本） |
| `v10.enc` / `v10.plain` | v1.0，无 salt，会话密钥是原始字节 |
| `nocomp.enc` / `nocomp.plain` | `compress=0`，数据段没有 LZ4 |
| `badmd5.enc` / `badmd5.plain` | 内容完全合法，只有**末尾 metadata 块**里的 `file_md5` 被改坏 |
| `not_encrypted.txt` | 普通文件，用于验证「不是加密文件」的分支 |

样本密码都是 `test-password`；`v31`/`badmd5`/`nocomp` 的 salt 是 `RL8lbK6x`
（真实文件的 salt 也是 8 字符）。

> ⚠️ 目录里的 `.gitattributes` 声明了 `* -text`，**不要删**。
> `.plain` 是纯文本，如果不声明就会被 `core.autocrlf` 转成 CRLF，
> 解密结果和样本对不上，测试在 Windows 上会直接失败。

## 为什么用 Python 生成的样本

这些文件由一份**独立的 Python 实现**生成，与 Go 实现互为交叉验证 ——
避免"自己和自己对答案"（比如 KDF 写错了，加密解密都用同一个错误实现，round-trip 照样通过）。

生成脚本没有随驱动一起提交，因为它依赖 `pycryptodomex` 和 `lz4`。
如果需要重新生成或新增样本，参照
[syndecrypt](https://github.com/anojht/synology-cloud-sync-decrypt-tool) 的读取逻辑
写一个对称的写入器即可，格式要点：

```
"__CLOUDSYNC_ENC__"          16 字节 magic
MD5(magic) 的 hex，32 字节
[metadata A]                 0x42 字典，以 0x40 结束；含 enc_key1/salt/version/compress/encrypt 等
[data 块 × N]                0x42 字典，{"type":"data","data":<bytes>}，每块 16 字节对齐
[metadata B]                 只有 {"type":"metadata","file_md5":"..."}
```

TLV 编码：`0x42` 字典 / `0x11` 字节串 / `0x10` 字符串 / `0x01` 整数，
长度字段一律 **2 字节大端**。

## 格式来源

算法与容器结构依据开源实现反推，与群晖官方闭源工具等价：

- https://github.com/marnix/synology-decrypt
- https://github.com/anojht/synology-cloud-sync-decrypt-tool
- https://github.com/cdredfox/synology-cloud-sync-decrypt-tool

并已对照一个真实的 Cloud Sync 加密文件核对过（version 3.1、salt 8 字符、
`compress`/`encrypt` 均为 1、数据块 8192 字节、metadata A 799 字节）。
