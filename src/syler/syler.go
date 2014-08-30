package main

import (
	"flag"
	"fmt"
	toml "github.com/stvp/go-toml-config"
	"igongpai"
	"path/filepath"
	"syler/auth"
	"syler/component"
	"syler/config"
	"syler/i"
)

func main() {
	//http server
	//radius avp server
	//radius accounting server

	// go func() {
	// 	res, err := v1.Challenge(net.IPv4(192, 168, 10, 254), *config.PortalSecret, net.IPv4(192, 168, 56, 2))
	// }()

	path := flag.String("config", "./syler.conf", "设置配置文件的路径")
	i.ExtraAuth = igongpai.NewAuthService()
	basic := auth.NewAuthService()
	component.CommonHttpHandler = basic
	component.CommonChapAuth = basic
	component.CommonPapAuth = basic
	flag.Parse()
	*path = filepath.FromSlash(*path)
	if err := toml.Parse(*path); err == nil {
		component.InitLogger()
		go component.StartHuawei()
		if *config.RadiusEnable {
			go component.StartRadiusAuth()
			go component.StartRadiusAcc()
		}
		component.StartHttp()
	} else {
		fmt.Println("配置文件解析错误，请重试")
	}

}
