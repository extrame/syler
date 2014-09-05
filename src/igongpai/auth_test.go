package igongpai

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"testing"
)

func TestAuth(t *testing.T) {
	h := md5.New()
	h.Write([]byte{0x27})
	h.Write([]byte("123456"))
	h.Write([]byte{0xd3, 0x49, 0x91, 0x87, 0x39, 0x6f, 0xf1, 0xe5, 0xe9, 0xa5, 0x9f, 0x73, 0x0f, 0x87, 0x2f, 0x73})
	wanted := []byte{0x84, 0xb9, 0x58, 0xfa, 0x66, 0x63, 0x98, 0xc8, 0x8c, 0x73, 0xc3, 0xc3, 0xbe, 0xd9, 0x85, 0xf7}
	if bytes.Compare(wanted, h.Sum(nil)) != 0 {
		t.Fail()
	}
}

func TestUnmarshal(t *testing.T) {
	r := new(RemoteResponse)
	json.Unmarshal([]byte(`{"C":"","S":200,"D":{"publickey":"","agentip":"","agentport":0,"resultcode":0,"resultmsg":"success"},"E":null}`), r)
	fmt.Println(r.D.ResultCode)
}

func TestMarshal(t *testing.T) {
	r := new(ResultResponse)
	r.ResultCode = 0
	bts, _ := json.Marshal(r)
	fmt.Println(string(bts))
}
