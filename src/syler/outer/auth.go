package outer

import ()

type AuthInfo struct {
	Name      []byte
	Pwd       []byte
	PublicKey []byte
	Timeout   uint32
}

type AuthService interface {
	Auth(*AuthInfo) (error, string)
}
