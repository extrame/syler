package component

import (
	"crypto/md5"
	"encoding/hex"
	"syler/config"
)

type AuthInfo struct {
	Name      []byte
	Pwd       []byte
	PublicKey []byte
	Timeout   uint32
}

var AuthingUser map[string]AuthInfo

func CalcSecret(authinfo AuthInfo) string {
	pwdhelper := md5.New()
	pwds := pwdhelper.Sum(authinfo.Pwd)

	md5helper := md5.New()
	md5helper.Write(authinfo.Name)
	md5helper.Write(pwds)
	md5helper.Write([]byte(*config.ProxyId))
	md5helper.Write(authinfo.PublicKey)
	return hex.EncodeToString(md5helper.Sum(nil))
}
