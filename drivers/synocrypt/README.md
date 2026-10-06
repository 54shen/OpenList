# synocrypt — 群晖 Cloud Sync 加密备份实时解密驱动

把群晖 **Cloud Sync 客户端加密**（`__CLOUDSYNC_ENC__`）的文件在 OpenList 里解密后挂载出来，
浏览、预览、下载看到的都是明文。

这是一个**叠加型驱动**：它自己不去访问网盘，而是引用本实例里已经挂好的另一个存储
（`remote_path`），在读取时把明文还原出来。同类驱动见 `drivers/crypt`、`drivers/alias`。

## 适用范围

| 群晖的加密方式 | 是否适用 |
|---|---|
| **Cloud Sync 客户端加密**（同步到公有云时勾选「启用加密」） | ✅ 本驱动 |
| 加密共享文件夹（eCryptfs，文件名带 `ECRYPTFS_FNEK_ENCRYPTED.`） | ❌ 完全不同的格式 |
| Hyper Backup 加密备份（`.hbk`，分块池 + 索引） | ❌ 不是一文件一密文，语义不匹配 |

判断方法：用十六进制编辑器看文件开头，出现 `__CLOUDSYNC_ENC__` 就是本驱动适用的那种。

## 用法

1. 先在 OpenList 里把网盘挂好（例如百度网盘，挂到 `/百度网盘`）
2. 新建存储 → 驱动选 **SynoCrypt**
   - `remote_path`：密文所在的挂载路径，如 `/百度网盘/群晖备份`
   - `password`：Cloud Sync 同步任务里设的加密密码
   - `salt`：**一般留空**。Cloud Sync 3.0+ 的每个加密文件头部自带 salt，驱动会自己读；
     只有 1.0 的老归档才需要手填
   - `cache_dir` / `cache_max_mb` / `cache_ttl_min`：明文缓存，见下
3. 保存后即可浏览

## 实现要点

### 为什么 List 不用解密

Cloud Sync 的加密**只加密文件内容，文件名和目录结构都是明文**。
所以目录列表可以直接透传底层存储，一行解密代码都不用写——
这也是它比 rclone crypt（文件名也加密）好做得多的根本原因。

### 读取是「边下载边解密」的

数据段的格式是「**跨块连续的 AES-256-CBC + 一整条 LZ4 流**」：

- CBC 的链式状态跨数据块延续 → 单独一块解不开
- 压缩是**一整条 LZ4 流**，没有分块索引 → 想读文件中间某段，必须从头解压

也就是说这个格式**天生做不到真正的随机访问**（对比 rclone crypt 用 AES-CTR，天生可寻址）。

如果等整个文件解完再提供读取，放一个 4GB 的视频就得先等 4GB 全部下载+解密完才出画面。
所以这里的做法是：**解密在后台 goroutine 里顺序推进并落盘，读取方只等待自己需要的那一段**
（`progressive.go`）。于是：

| 操作 | 行为 |
|---|---|
| 从头播放 | 解出几 MB 就出画面，边下边播 |
| 向后拖进度条 | 已经解过的部分**立即**返回 |
| 向前拖进度条 | 等解密游标追上目标偏移（受限于下载速度） |
| 全部解完后 | 等同于本地文件，任意跳转即时 |

**向前拖动不是"瞬间"的**，这是格式决定的硬边界，不是实现偷懒 —— 目标偏移之前的密文
必须先解压过。缓存全部解完之后就没有这个限制了。

### 完整性校验的取舍

`file_md5` 是**整个文件**的摘要，只有全部解完才知道对不对。为了能立刻开始播放，
数据可能在校验完成前就发出去了 —— 这是流式必须付的代价。

处理方式：
- 校验失败时**中断正在进行的所有读取**（读取方每次 Read 都会检查），下载工具会立刻
  发现响应被截断，而不是拿到一份"看起来完整"的坏数据
- 失败会被记住，**后续请求直接失败**，不会重复下载同一个坏文件
- 缓存文件被删除

> 密码错误不会走到这里：`key1_hash` 在解密开始前就挡住了。

### 非加密文件的透传

同一个目录里可能混着 `@SynologyCloudSync/cloudsync_encrypt.info`、缩略图、
或本来就没加密的文件。`Link` 会先读文件头 18 字节探测：
不是 `__CLOUDSYNC_ENC__` 就把底层链接**原样返回**，不做任何处理。

### 为什么列表里的「大小」要单独处理

目录列表报的是**密文大小**，比明文大。这在多数场景下只是显示不精确，但有一个硬故障：

框架在代理响应里是这样定长度的（`server/common/proxy.go`）：

```go
size := link.ContentLength
if size <= 0 {
    size = file.GetSize()   // ← 回退到列表里报的大小
}
```

对**0 字节的明文**来说 `ContentLength` 就是 0，框架于是回退去按密文大小（比如 468）读，
而实际只能给出 0 字节 → `EOF` 报错。

所以必须知道明文大小。做法：

1. **先试最便宜的**：只读文件开头 8KB，解出 metadata 和第一个数据块的前 16 字节，
   从 **LZ4 帧头**里取 content size。
2. **帧头没存大小就完整解密数一遍**——空文件正是这种情况
   （实测 Python 的 `lz4.frame` 对空输入产出 `FLG=0x60`，不带 content size）。
   因为只对小于 8KB 的文件这么做，代价可忽略。
3. 结果写进**持久化的大小缓存**（`<cacheDir>/sizes.json`），以后列表直接命中。

`probe_size` 开关决定要不要对**大文件**也做第 1 步。默认关闭，
因为每个文件都要多一次很小的头部读取，网盘目录很大时会明显变慢。
小于 8KB 的文件无论如何都会探测（它们便宜，且 0 字节文件都在这个区间）。

## 格式与算法参考

算法完全依据开源实现反推，与群晖官方闭源工具等价：

- https://github.com/marnix/synology-decrypt （最初的命令行工具）
- https://github.com/anojht/synology-cloud-sync-decrypt-tool （Python，含 GUI）
- https://github.com/cdredfox/synology-cloud-sync-decrypt-tool （Go 实现）

容器结构（**已用真实文件核对**）：

```
"__CLOUDSYNC_ENC__"          16 字节 magic
MD5(magic) 的 hex，32 字节    magic 校验
[metadata 块 A]               密钥信息：enc_key1 / enc_key2 / salt / key1_hash /
                              session_key_hash / version / compress / encrypt /
                              file_name / key2_hash / digest
[data 块 × N]                 每块 8192 字节（实测），必须 16 字节对齐
[metadata 块 B]               ★ 只有 {type: metadata, file_md5: "..."}
```

**注意 `file_md5` 在文件末尾的第二块里，不在开头那块。**
只读开头那块会拿不到摘要，完整性校验就形同虚设——实现时必须全程捕获、读完再比对。

TLV 编码：`0x42` 字典（以 `0x40` 结束）/ `0x11` 字节串 / `0x10` 字符串 / `0x01` 整数，
长度字段都是 **2 字节大端**（因此单块上限 65535 字节，且必须 16 字节对齐）。

密钥流程：

```
KDF(密码, salt)                 = OpenSSL EVP_BytesToKey(MD5)，有 salt 时 1000 轮
会话密钥 = AES-256-CBC 解 enc_key1  → 去 PKCS#7
   （另一条路是用 RSA-OAEP 解 enc_key2，需要 private.pem；本驱动暂未实现）
   v3.x：会话密钥是 hex 字符串，先转字节
   v1.0：会话密钥是原始字节
数据密钥 = KDF(会话密钥, 无 salt)   → 只 1 轮
数据    = AES-256-CBC(连续) → 去 PKCS#7 → [compress=1 时] LZ4 frame 解压
完整性  = MD5(明文) 必须等于末尾 metadata 块的 file_md5
```

密码提前校验：`key1_hash` = `salt10 + md5(salt10 + password)`，
在解会话密钥之前就能判断密码对不对，避免报出难懂的填充错误。

### 实测的真实文件特征（v3.1）

用本机一个真实的 Cloud Sync 加密文件（339302 字节）核对：

| 项 | 实测值 |
|---|---|
| version | **3.1** |
| salt | 8 字符 |
| compress / encrypt | 都是 **1** |
| 数据块大小 | **8192** 字节，共 42 块 |
| metadata 块 A | **799** 字节 |
| metadata 块 B | 只有 `file_md5` |
| 其它字段 | `file_name`（与云端文件名一致 → **文件名确实不加密**）、`key2_hash` |

因此 `probeReadBytes = 4096` 对 799 字节的 metadata 有 5 倍余量。

## 自测

`container.go` 只依赖 `pierrec/lz4/v4`，没有任何 OpenList 内部依赖，
所以可以单独拉出来测（改算法时建议先在这里验，秒级编译）：

```bash
# 用 Python 造样本（需 pycryptodomex + lz4）
python _make_fixtures.py fixtures
# 用 Go 解密比对
cd synocrypt-test && go run . ../fixtures
```

覆盖用例：v3.0 带 salt / v1.0 无 salt / 空文件 / 错误密码必须被拒 / 非加密文件识别 / salt 覆盖。

## 已知限制

- **不支持私钥解密**（`enc_key2` / `private.pem` 那条路径）。目前只走密码。
  真实文件的 metadata 里确实带 `enc_key2`，如果密码丢了但有 `key.zip`，
  需要补一段 `crypto/rsa` + `PKCS1_OAEP` 的分支（注意 OAEP 的哈希算法待确认，
  本机那把 `private.pem` 用 SHA1/SHA256/SHA512/SHA3-256 都解不开对应文件的 `enc_key2`，
  推测它不是该文件的密钥）。
- 大于 8KB 的文件，在 `probe_size` 关闭时列表里显示的是密文大小（略大）。
  打开该文件后真实大小会被记住，之后的列表就准了。要一开始就精确就打开 `probe_size`。
- 缓存淘汰时如果文件正被读取，Windows 下删除会失败（共享冲突），该文件会留到关闭后才可能被清。
- 底层驱动的 `RangeReader` 必须可重复调用（探测一次 + 全量读一次）。

## 验证状态

| 层次 | 状态 |
|---|---|
| 结构解析（TLV / 两块 metadata / 8192 数据块） | ✅ 已在**真实文件**上核对 |
| 算法正确性（KDF / AES-CBC / LZ4 / MD5） | ✅ 合成样本逐字节验证，样本已严格对齐真实布局 |
| 完整性校验确实生效 | ✅ 用「摘要被篡改」的样本证明 |
| 端到端（挂载 → 预览 → 区间读取） | ✅ 18 项全过 |
| **用真实文件的密码解出明文** | ⏳ **待验证** —— 需要用户提供密码 |
