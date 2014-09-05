package component

import (
	"crypto/md5"
	"fmt"
	"strings"
	"testing"
)

func TestCallBack(t *testing.T) {

}

func TestMd5UserPwd(t *testing.T) {
	h := md5.New()
	h.Write([]byte("mink2501"))
	h.Write([]byte{0x27, 0x08, 0x7c, 0x59, 0x6a, 0xd1, 0x31, 0xee, 0x5a, 0x39, 0x10, 0x10, 0x4d, 0xcb, 0x46, 0x48})
	oct := h.Sum(nil)
	fmt.Printf("%03x\n", oct)
	tested := []byte("b8f6b11c8f9b")
	fmt.Printf("%03x\n", tested)
	b := make([]byte, len(oct))
	for i := 0; i < len(oct); i++ {
		if i < len(tested) {
			b[i] = oct[i] ^ tested[i]
		} else {
			b[i] = oct[i]
		}

	}
	fmt.Printf("%03x\n", b)
}

func TestFielded(t *testing.T) {
	fmt.Println(strings.FieldsFunc("aabb-ccdd-eeff", func(s rune) bool {
		return s == '-' || s == ':'
	}))
}
