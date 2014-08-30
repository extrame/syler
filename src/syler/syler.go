package main

import (
	"flag"
	"fmt"
	toml "github.com/stvp/go-toml-config"
	"igongpai"
	"path/filepath"
	"syler/component"
	"syler/config"
	"syler/outer"
)

func main() {
	//http server
	//radius avp server
	//radius accounting server

	// go func() {
	// 	res, err := v1.Challenge(net.IPv4(192, 168, 10, 254), *config.PortalSecret, net.IPv4(192, 168, 56, 2))
	// }()

	component.AuthingUser = make(map[string]outer.AuthInfo)
	path := flag.String("config", "./syler.conf", "设置配置文件的路径")
	component.AddOuterAuth(igongpai.AuthService{})
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
