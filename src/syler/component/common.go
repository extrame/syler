package component

import (
	"crypto/md5"
	"encoding/hex"
	"syler/config"
	"syler/outer"
)

var AuthingUser map[string]outer.AuthInfo
