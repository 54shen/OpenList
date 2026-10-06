package synocrypt

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

// Addition 是「添加存储」页面上的表单字段。
//
// 只需要两样东西：密文在哪、密码是什么。
// salt 不用手填——Cloud Sync 3.0 以上的每个加密文件头部自带 salt，驱动会自己读。
type Addition struct {
	RemotePath string `json:"remote_path" type:"string" required:"true" help:"加密数据所在的挂载路径。先在 OpenList 里挂好网盘，再填那个挂载里的目录，例如 /百度网盘/群晖备份"`

	Password string `json:"password" type:"string" required:"true" help:"Cloud Sync 同步任务里设置的加密密码"`

	Salt string `json:"salt" type:"string" help:"一般留空。只有 Cloud Sync 1.0 的老归档（文件头里没有 salt）才需要手填"`

	CacheDir    string `json:"cache_dir" type:"string" default:"data/temp/synocrypt" help:"解密后的明文缓存目录。留空用 data/temp/synocrypt；相对路径相对于 OpenList 的工作目录"`
	CacheMaxMB  int    `json:"cache_max_mb" type:"number" default:"8192" help:"缓存占用上限（MB），超出后按最久未使用淘汰"`
	CacheTTLMin int    `json:"cache_ttl_min" type:"number" default:"1440" help:"缓存最长保留时间（分钟），默认 24 小时"`

	ProbeSize bool `json:"probe_size" type:"bool" default:"false" help:"列表里显示精确的明文大小。开启后每个文件会多一次很小的头部读取，网盘目录很大时会明显变慢；关闭时列表里显示的是密文大小（略大）。小于 8KB 的文件无论开关都会探测"`

	ShowHidden bool `json:"show_hidden" type:"bool" default:"false" help:"显示隐藏文件"`
}

var config = driver.Config{
	Name: "SynoCrypt",
	// 本驱动不返回直链，只能走服务端代理
	OnlyProxy:   true,
	NoLinkURL:   true,
	CheckStatus: true,
	DefaultRoot: "/",
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &SynoCrypt{}
	})
}

// GetRootPath 让框架知道「本存储的根」其实落在底层挂载的哪个路径上。
// 框架在 op.Get(..., "/") 时会把对象的 Path 设成这里返回的值，
// 之后 List 拿到的 dir.GetPath() 就已经是底层路径了。
func (a Addition) GetRootPath() string {
	return a.RemotePath
}
