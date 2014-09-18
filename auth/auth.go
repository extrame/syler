package auth

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/extrame/syler/component"
	"github.com/extrame/syler/config"
	"github.com/extrame/syler/i"
	"log"
	"net"
	"net/http"
	"strconv"
)

type AuthInfo struct {
	Name    []byte
	Pwd     []byte
	Mac     net.HardwareAddr
	Timeout uint32
}

type AuthServer struct {
	authing_user map[string]AuthInfo
}

func (a *AuthServer) AuthChap(username []byte, chapid byte, chappwd, chapcha []byte, userip net.IP, usermac net.HardwareAddr) (err error, to uint32) {
	if info, ok := a.authing_user[userip.String()]; ok {
		if bytes.Compare(username, info.Name) == 0 && i.TestChapPwd(chapid, info.Pwd, chapcha, chappwd) {
			to = info.Timeout
			info.Mac = usermac
			return
		}
	} else {
		err = fmt.Errorf("radius auth - no such user ", userip.String())
	}
	return
}

func (a *AuthServer) AuthMac(mac net.HardwareAddr, userip net.IP) (error, uint32) {
	return fmt.Errorf("unsupported mac auth on %s", userip.String()), 0
}

func (a *AuthServer) AuthPap(username, userpwd []byte, userip net.IP) (err error, to uint32) {
	if info, ok := a.authing_user[userip.String()]; ok {
		if bytes.Compare(info.Pwd, userpwd) == 0 {
			to = info.Timeout
		}
	} else {
		err = fmt.Errorf("radius auth - no such user ", userip.String())
	}
	return
}

func (a *AuthServer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var err error
	if config.IsValidClient(r.RemoteAddr) {
		timeout := r.FormValue("timeout")
		nas := r.FormValue("nasip")
		userip_str := r.FormValue("userip")
		username := []byte(r.FormValue("username"))
		userpwd := []byte(r.FormValue("userpwd"))
		var to uint64
		to, err = strconv.ParseUint(timeout, 10, 32)

		userip := net.ParseIP(userip_str)
		if userip == nil {
			if *config.UseRemoteIpAsUserIp == true {
				ip, _, _ := net.SplitHostPort(r.RemoteAddr)
				userip = net.ParseIP(ip)
			} else {
				err = fmt.Errorf("UserIp is not available and UseRemoteIpAsUserIp is false")
			}
		}

		if userip != nil {
			if basip := net.ParseIP(nas); basip != nil {
				log.Printf("got a login request from %s on nas %s\n", userip, basip)
				if len(username) == 0 {
					log.Println("username len = 0")

					if *config.RandomUser {
						username, userpwd = a.RandomUser(userip, basip, *config.HuaweiDomain, []byte{}, uint32(to))
					} else {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				} else {
					username = []byte(string(username) + "@" + *config.HuaweiDomain)
					a.authing_user[userip.String()] = AuthInfo{username, userpwd, uint32(to)}
				}
				if err = component.Auth(userip, basip, uint32(to), username, userpwd); err == nil {
					w.WriteHeader(http.StatusOK)
					w.Write(a.authing_user[userip.String()].Mac)
					return
				}
			} else {
				err = fmt.Errorf("Parse Ip err from %s", nas)
			}
		}
	} else {
		err = fmt.Errorf("Not Allowed from this IP")
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(err.Error()))
}

func (a *AuthServer) RandomUser(userip, nasip net.IP, domain string, timeout uint32) ([]byte, []byte) {
	hash := md5.New()
	hash.Write(userip)
	hash.Write(nasip)
	bts := hash.Sum(nil)
	username := []byte(userip.String())
	app := []byte("@" + domain)
	if len(username)+len(app) > 32 {
		username = username[:32-len(app)]
	}
	fname := append(username, app...)
	userpwd := bts
	a.authing_user[userip.String()] = AuthInfo{username, userpwd, []byte{}, timeout}
	return fname, userpwd
}

func NewAuthService() *AuthServer {
	s := new(AuthServer)
	s.authing_user = make(map[string]AuthInfo)
	return s
}
