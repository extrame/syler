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
	md5helper := md5.New()
	md5helper.Write(authinfo.Name)
	md5helper.Write(authinfo.Pwd)
	md5helper.Write([]byte(*config.ProxyId))
	md5helper.Write(authinfo.PublicKey)
	return hex.EncodeToString(md5helper.Sum(nil))
}
