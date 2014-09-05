package igongpai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	toml "github.com/stvp/go-toml-config"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syler/component"
	"syler/config"
)

type UserAuthInfo struct {
	username []byte
	chapid   byte
	chapcha  []byte
	chappwd  []byte
	timeout  uint32
}

type MacAuthInfo struct {
	mac     []byte
	timeout uint32
}

type AuthServer struct {
	ProxyId      *string
	RemoteServer *string
	NasIp        *string
}

type RemoteResponse struct {
	S int
	D ResultResponse
	E string
}

type ResultResponse struct {
	ResultCode int `json:"resultcode"`
}

func (a *AuthServer) AuthChap(username []byte, chapid byte, chappwd, chapcha []byte, userip net.IP) (err error, to uint32) {
	info := UserAuthInfo{username, chapid, chapcha, chappwd, 0}
	if err = info.TestAgainstRemote(*a.RemoteServer, *a.ProxyId); err == nil {
		to = info.timeout
	}
	return
}

func (a *AuthServer) AuthMac(username []byte, userip net.IP) (err error, to uint32) {
	info := MacAuthInfo{username, 0}
	if err = info.TestAgainstRemote(*a.RemoteServer, *a.ProxyId); err == nil {
		to = info.timeout
	}
	return
}

func (a *AuthServer) AuthPap(username []byte, userpwd []byte, userip net.IP) (err error, to uint32) {
	return errors.New("not supported yet"), 0
}

func (a *AuthServer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", *a.RemoteServer)
	var err error
	if config.IsValidClient(r.RemoteAddr) {
		timeout := r.FormValue("timeout")

		username := r.FormValue("username")
		userpwd := []byte(r.FormValue("userpwd"))
		var to uint64
		to, err = strconv.ParseUint(timeout, 10, 32)

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		userip := net.ParseIP(ip)
		nas := *a.NasIp

		if basip := net.ParseIP(nas); basip != nil {
			log.Printf("got a login request from %s on nas %s\n", userip, basip)
			username = username + "@" + *config.HuaweiDomain
			if err = component.Auth(userip, basip, uint32(to), []byte(username), userpwd); err == nil {
				r := new(ResultResponse)
				r.ResultCode = 0
				bts, _ := json.Marshal(r)
				w.Write(bts)
				w.WriteHeader(http.StatusOK)
				return
			}
		} else {
			err = fmt.Errorf("Parse Ip err from %s", nas)
		}
	} else {
		err = fmt.Errorf("Not Allowed from this IP")
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(err.Error()))
}

type UserRemoteReq struct {
	ChapId  string `json:"chapid"`
	ChapCha string `json:"chapcha"`
	ChapPwd string `json:"chappwd"`
	ProxyId string `json:"proxyid"`
}

func (info *UserAuthInfo) TestAgainstRemote(remoteserver, proxyid string) (err error) {
	req := new(UserRemoteReq)
	req.ChapId = base64.StdEncoding.EncodeToString([]byte{info.chapid})
	req.ChapCha = base64.StdEncoding.EncodeToString(info.chapcha)
	req.ChapPwd = base64.StdEncoding.EncodeToString(info.chappwd)
	req.ProxyId = proxyid

	shortname := string(info.username)

	var result *http.Response
	if bts, err := json.Marshal(req); err == nil {
		if result, err = http.Post(remoteserver+"/u/"+shortname+".json", "application/json", bytes.NewReader(bts)); err == nil {
			if result.StatusCode != 200 {
				err = fmt.Errorf("remote server response bad status code")
			} else {
				var res []byte
				res, err = ioutil.ReadAll(result.Body)
				defer result.Body.Close()
				remoteres := new(RemoteResponse)
				json.Unmarshal(res, remoteres)
				if remoteres.S >= 300 {
					err = fmt.Errorf("Remote server response no success code")
				}
			}
		}
	}
	return
}

func (info *MacAuthInfo) TestAgainstRemote(remoteserver, proxyid string) (err error) {

	var result *http.Response
	if result, err = http.Post(remoteserver+"/mac/"+string(info.mac)+".json", "application/json", bytes.NewBufferString(`{"proxyid":"`+proxyid+`"}`)); err == nil {
		if result.StatusCode != 200 {
			err = fmt.Errorf("remote server response bad status code")
		} else {
			var res []byte
			res, err = ioutil.ReadAll(result.Body)
			defer result.Body.Close()
			remoteres := new(RemoteResponse)
			json.Unmarshal(res, remoteres)
			if remoteres.S >= 300 {
				err = fmt.Errorf("Remote server response no success code")
			}
		}
	}
	return
}

func NewAuthService() *AuthServer {
	s := new(AuthServer)
	return s
}

func (a *AuthServer) IsConfigValid() bool {
	ip := net.ParseIP(*a.NasIp)
	*a.RemoteServer = strings.TrimSuffix(*a.RemoteServer, "/")
	return !ip.To4().IsUnspecified()
}

func (a *AuthServer) AddConfig() {
	a.ProxyId = toml.String("basic.local_proxy_id", "1")
	a.RemoteServer = toml.String("basic.remote_server_address", "http://121.42.12.146:8080/")
	a.NasIp = toml.String("basic.nas_ip", "")
}
