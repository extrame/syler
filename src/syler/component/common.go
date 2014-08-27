package component

type AuthInfo struct {
	Name    []byte
	Pwd     []byte
	Timeout uint32
}

var AuthingUser map[string]AuthInfo
