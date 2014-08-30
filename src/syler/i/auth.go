package i

import (
	"crypto/md5"
	"net"
	"net/http"
)

type ChapAuthService interface {
	AuthChap(username []byte, chapid byte, chappwd, chapcha []byte, userip net.IP) (error, uint32)
}

type PapAuthService interface {
	AuthPap(username, userpwd []byte, userip net.IP) (error, uint32)
}

type HttpHandler interface {
	HandleLogin(w http.ResponseWriter, r *http.Request)
}

var ExtraAuth interface{}

//utils function to test agent chap password
func TestChapPwd(chapid byte, testedpwd, chapcha, chappwd []byte) bool {
	hash := md5.New()
	hash.Write([]byte{chapid})
	hash.Write(testedpwd)
	hash.Write(chapcha)
	tested := hash.Sum(nil)
	for i := 0; i < len(tested); i++ {
		if tested[i] != chappwd[i] {
			return false
		}
	}
	return true
}
