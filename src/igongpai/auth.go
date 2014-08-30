package igongpai

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"syler/config"
	"syler/outer"
)

func CalcSecret(authinfo outer.AuthInfo) string {
	pwdhelper := md5.New()
	pwds := pwdhelper.Sum(authinfo.Pwd)

	md5helper := md5.New()
	md5helper.Write(authinfo.Name)
	md5helper.Write(pwds)
	md5helper.Write([]byte(*config.ProxyId))
	md5helper.Write(authinfo.PublicKey)
	return hex.EncodeToString(md5helper.Sum(nil))
}

type AuthServer struct {
}

type RemoteResponse struct {
	ResultCode int `json:"resultcode"`
}

func (a *AuthServer) Auth(info outer.AuthInfo) (err error, msg string) {
	secert := CalcSecret(info)
	requestvalue := make(url.Values)
	requestvalue.Set("username", string(info.Name[:len(info.Name)]))
	requestvalue.Set("secret", secert)
	err = fmt.Errorf("error")

	result, err := http.Post(*config.RemoteServer, "application/json", strings.NewReader(requestvalue.Encode()))
	if err != nil || result.StatusCode != 200 {
		msg = fmt.Sprint("remote server response: ", err.Error())
	} else {
		res, err := ioutil.ReadAll(result.Body)
		defer result.Body.Close()
		if err != nil {
			msg = fmt.Sprint("Remote server Response Prase err", err.Error())
		}
		remoteres := new(RemoteResponse)
		json.Unmarshal(res, remoteres)
		if remoteres.ResultCode == 0 {
			err = nil
		} else {
			msg = fmt.Sprint("Remote server response no success code")
		}
	}
	return
}
