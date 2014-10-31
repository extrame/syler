package component

import (
	"fmt"
	"github.com/extrame/syler/config"
	"github.com/extrame/syler/huawei/portal"
	"github.com/extrame/syler/huawei/portal/v1"
	"github.com/extrame/syler/huawei/portal/v2"
	"log"
	"net"
	"net/http"
)

func StartHuawei() {
	portal.Timeout = *config.HuaweiTimeout
	portal.RegisterFallBack(func(msg portal.Message, src net.IP) {
		log.Println(" type: ", msg.Type())
		if msg.Type() == portal.NTF_LOGOUT {
			BASIC_SERVICE.NotifyLogout(msg.UserIp(), src)
		}
	})
	if *config.HuaweiVersion == 1 {
		portal.SetVersion(new(v1.Version))
	} else {
		portal.SetVersion(new(v2.Version))
	}

	portal.ListenAndService(fmt.Sprintf(":%d", *config.HuaweiPort))
}

func Challenge(userip net.IP, basip net.IP) (response portal.Message, err error) {
	return portal.Challenge(userip, *config.HuaweiSecret, basip, *config.HuaweiNasPort)
}

func Auth(userip net.IP, basip net.IP, timeout uint32, username, userpwd []byte) (err error) {
	var res portal.Message
	if res, err = Challenge(userip, basip); err == nil {
		if cres, ok := res.(portal.ChallengeRes); ok {
			res, err = portal.ChapAuth(userip, *config.HuaweiSecret, basip, *config.HuaweiNasPort, username, userpwd, res.ReqId(), cres.GetChallenge())
			if err == nil {
				res, err = portal.AffAckAuth(userip, *config.HuaweiSecret, basip, *config.HuaweiNasPort, res.SerialId(), res.ReqId())
			}
		}
	}
	return
}

func Logout(userip net.IP, secret string, basip net.IP) (response portal.Message, err error) {
	return portal.Logout(userip, *config.HuaweiSecret, basip, *config.HuaweiNasPort)
}

func callBackOffline(url string, userip, netip net.IP) {
	if url != "" {
		http.Get(url + "?userip=" + userip.String() + "&nas=" + netip.String())
	}
}
