package component

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/extrame/syler/config"
	"github.com/extrame/syler/i"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
)

type AuthInfo struct {
	Name    []byte
	Pwd     []byte
	Mac     net.HardwareAddr
	Timeout uint32
}

type AuthServer struct {
	authing_user map[string]*AuthInfo
}

var BASIC_SERVICE = new(AuthServer)

func InitBasic() {
	BASIC_SERVICE.authing_user = make(map[string]*AuthInfo)
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
		if *config.NasIp != "" {
			nas = *config.NasIp
		}
		userip_str := r.FormValue("userip")
		username := []byte(r.FormValue("username"))
		userpwd := []byte(r.FormValue("userpwd"))
		var to uint64
		to, err = strconv.ParseUint(timeout, 10, 32)

		if to == 0 && *config.DefaultTimeout != 0 {
			to = *config.DefaultTimeout
		}

		userip := net.ParseIP(userip_str)
		if *config.UseRemoteIpAsUserIp == true {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			userip = net.ParseIP(ip)
		} else if userip == nil {
			u_refer := r.Header.Get("Referer")
			var u *url.URL
			if u, err = url.Parse(u_refer); err == nil {
				if uip := u.Query().Get("userip"); uip != "" {
					userip = net.ParseIP(userip_str)
				} else {
					err = fmt.Errorf("请求解析Referer错误")
				}
			} else {
				err = fmt.Errorf("配置错误！请联系管理员")
			}
		}
		var full_username []byte
		if userip != nil {
			if basip := net.ParseIP(nas); basip != nil {
				log.Printf("got a login request from %s on nas %s\n", userip, basip)
				if len(username) == 0 {
					if *config.RandomUser {
						full_username, userpwd = a.RandomUser(userip, basip, *config.HuaweiDomain, uint32(to))
					} else {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				} else {
					full_username = []byte(string(username) + "@" + *config.HuaweiDomain)
					a.authing_user[userip.String()] = &AuthInfo{username, userpwd, []byte{}, uint32(to)}
				}
				if err = Auth(userip, basip, uint32(to), []byte(full_username), userpwd); err == nil {
					w.Write([]byte(a.authing_user[userip.String()].Mac.String()))
					return
				}
			} else {
				err = fmt.Errorf("NAS IP配置错误")
			}
		}
	} else {
		err = fmt.Errorf("该IP不在配置可允许的用户中")
	}
	if err != nil {
		log.Println("login error: ", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}
}

//处理Logout请求
func (a *AuthServer) HandleLogout(w http.ResponseWriter, r *http.Request) {
	var err error
	nas := r.FormValue("nasip") //TODO
	userip_str := r.FormValue("userip")
	if userip := net.ParseIP(userip_str); userip != nil {
		if basip := net.ParseIP(nas); basip != nil {
			if _, err = Logout(userip, *config.HuaweiSecret, basip); err == nil {
				w.WriteHeader(http.StatusOK)
				return
			}
		} else {
			err = fmt.Errorf("Parse Ip err from %s", nas)
		}
	} else {
		err = fmt.Errorf("Parse Ip err from %s", userip_str)
	}
}

func (a *AuthServer) HandleRoot(w http.ResponseWriter, r *http.Request) {
	log.Println("Show login page")
	path := filepath.FromSlash(*config.LoginPage)
	http.ServeFile(w, r, path)
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
	a.authing_user[userip.String()] = &AuthInfo{username, userpwd, []byte{}, timeout}
	return fname, userpwd
}

func (a *AuthServer) AcctStart(username []byte, userip net.IP, nasip net.IP, usermac net.HardwareAddr, sessionid string) error {
	return nil
}

func (a *AuthServer) AcctStop(username []byte, userip net.IP, nasip net.IP, usermac net.HardwareAddr, sessionid string) error {
	callBackOffline(*config.CallBackUrl, userip, nasip)
	return nil
}

func (a *AuthServer) NotifyLogout(userip, nasip net.IP) error {
	callBackOffline(*config.CallBackUrl, userip, nasip)
	return nil
}
