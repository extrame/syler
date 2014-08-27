package v2

import (
	"crypto/md5"
	"fmt"
	"testing"
)

func TestRawAuth(t *testing.T) {
	hash := md5.New()
	hash.Write([]byte{2, 1, 0, 0, 0x14, 0xe, 0, 0, 0x6a, 0x78, 0x2b, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	hash.Write([]byte("ctbri4008118114"))
	bts := hash.Sum(nil)
	for _, v := range bts {
		fmt.Printf(" %02x", v)
	}

}
