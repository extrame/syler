package igongpai

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syler/component"
	"syler/config"
	"syler/i"
)

type AuthInfo struct {
	Name      []byte
	Pwd       []byte
	PublicKey []byte
	Timeout   uint32
}

type AuthServer struct {
	authing_user map[string]AuthInfo
}

type RemoteResponse struct {
	ResultCode int `json:"resultcode"`
}

func (a *AuthServer) AuthChap(username []byte, chapid byte, chappwd, chapcha []byte, userip net.IP) (err error, to uint32) {
	if info, ok := a.authing_user[userip.String()]; ok {
		if bytes.Compare(username, info.Name) == 0 && i.TestChapPwd(chapid, info.Pwd, chapcha, chappwd) {
			if err = info.TestAgainstRemote(); err == nil {
				to = info.Timeout
			}
		}
	} else {
		err = fmt.Errorf("radius auth - no such user ", userip.String())
	}
	return
}

func (a *AuthServer) AuthPap(username []byte, userpwd []byte, userip net.IP) (err error, to uint32) {
	if info, ok := a.authing_user[userip.String()]; ok {
		if bytes.Compare(username, info.Name) == 0 && bytes.Compare(info.Pwd, userpwd) == 0 {
			if err = info.TestAgainstRemote(); err == nil {
				to = info.Timeout
			}
		}
	} else {
		err = fmt.Errorf("radius auth - no such user ", userip.String())
	}
	return
}

func (a *AuthServer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", *config.RemoteServer)
	var err error
	if config.IsValidClient(r.RemoteAddr) {
		timeout := r.FormValue("timeout")
		nas := *config.NasIp
		username := []byte(r.FormValue("username"))
		userpwd := []byte(r.FormValue("userpwd"))
		publicKey := []byte(r.FormValue("publickey"))
		var to uint64
		to, err = strconv.ParseUint(timeout, 10, 32)

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		userip := net.ParseIP(ip)

		if userip != nil {
			if basip := net.ParseIP(nas); basip != nil {
				log.Printf("got a login request from %s on nas %s\n", userip, basip)
				if len(publicKey) != 0 {
					username = []byte(string(username) + "@" + *config.HuaweiDomain)
					a.authing_user[userip.String()] = AuthInfo{username, userpwd, publicKey, uint32(to)}
				} else { //pulibkey = 0
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if err = component.Auth(userip, basip, uint32(to), username, userpwd); err == nil {
					w.WriteHeader(http.StatusOK)
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

func (info *AuthInfo) TestAgainstRemote() (err error) {
	secert := info.CalcSecret()
	requestvalue := make(url.Values)
	requestvalue.Set("username", string(info.Name[:len(info.Name)]))
	requestvalue.Set("secret", secert)
	err = fmt.Errorf("error")

	var result *http.Response
	result, err = http.Post(*config.RemoteServer, "application/json", strings.NewReader(requestvalue.Encode()))
	if result.StatusCode != 200 {
		err = fmt.Errorf("remote server response bad status code")
	} else {
		var res []byte
		res, err = ioutil.ReadAll(result.Body)
		defer result.Body.Close()
		remoteres := new(RemoteResponse)
		json.Unmarshal(res, remoteres)
		if remoteres.ResultCode != 0 {
			err = fmt.Errorf("Remote server response no success code")
		}
	}
	return
}

func (a *AuthInfo) CalcSecret() string {
	pwdhelper := md5.New()
	pwds := pwdhelper.Sum(a.Pwd)

	md5helper := md5.New()
	md5helper.Write(a.Name)
	md5helper.Write(pwds)
	md5helper.Write([]byte(*config.ProxyId))
	md5helper.Write(a.PublicKey)
	return hex.EncodeToString(md5helper.Sum(nil))
}

func NewAuthService() *AuthServer {
	s := new(AuthServer)
	s.authing_user = make(map[string]AuthInfo)
	return s
}
