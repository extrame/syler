package config

import (
	toml "github.com/stvp/go-toml-config"
	"net"
	"strings"
)

var (
	RadiusEnable   = toml.Bool("radius.enabled", false)
	RadiusAuthPort = toml.Int("radius.port", 1812)
	RadiusAccPort  = toml.Int("radius.acc_port", 1813)
	RadiusSecret   = toml.String("radius.secret", "testing123")
	PortalSecret   = toml.String("portal.secret", "testing123")
	HttpPort       = toml.Int("http.port", 8080)
	HttpWhiteList  = toml.String("http.white_list", "")
	RandomUser     = toml.Bool("basic.random_user", true)
	LogFile        = toml.String("basic.logfile", "")
	CallBackUrl    = toml.String("basic.callback_logout", "")
	HuaweiPort     = toml.Int("huawei.port", 50100)
	HuaweiVersion  = toml.Int("huawei.version", 1)
	HuaweiTimeout  = toml.Int("huawei.timeout", 15)
	HuaweiSecret   = toml.String("huawei.secret", "testing123")
	HuaweiNasPort  = toml.Int("huawei.nas_port", 2000)
	HuaweiDomain   = toml.String("huawei.domain", "huawei.com")
	LoginPage      = toml.String("basic.login_page", "./login.html")
)

func IsValidClient(addr string) bool {
	if *HttpWhiteList == "" {
		return true
	}
	if ip, _, err := net.SplitHostPort(addr); err == nil {
		if strings.Contains(*HttpWhiteList, ip) {
			return true
		}
	}
	return false
}
