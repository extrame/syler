package v1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/extrame/syler/huawei/portal"
	"net"
)

type T_Message struct {
	Header T_Header
	Attrs  []T_Attr
}

func (t *T_Message) ReqId() uint16 {
	return t.Header.ReqIdentifier
}

func (t *T_Message) SerialId() uint16 {
	return t.Header.SerialNo
}

func (t *T_Message) UserIp() net.IP {
	return t.Header.UserIp
}

func (msg *T_Message) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, msg.Header.Version)
	binary.Write(buf, binary.BigEndian, msg.Header.Type)
	binary.Write(buf, binary.BigEndian, msg.Header.Pap)
	binary.Write(buf, binary.BigEndian, msg.Header.Rsv)
	binary.Write(buf, binary.BigEndian, msg.Header.SerialNo)
	binary.Write(buf, binary.BigEndian, msg.Header.ReqIdentifier)
	binary.Write(buf, binary.BigEndian, msg.Header.UserIp)
	binary.Write(buf, binary.BigEndian, msg.Header.UserPort)
	binary.Write(buf, binary.BigEndian, msg.Header.ErrCode)
	binary.Write(buf, binary.BigEndian, msg.Header.AttrNum)
	for _, v := range msg.Attrs {
		binary.Write(buf, binary.BigEndian, v.AttrType)
		binary.Write(buf, binary.BigEndian, v.AttrLen+2)
		binary.Write(buf, binary.BigEndian, v.AttrStr)
	}
	return buf.Bytes()
}

func (t *T_Message) Type() byte {
	return t.Header.Type
}

func (t *T_Message) GetChallenge() []byte {
	for i := byte(0); i < t.Header.AttrNum; i++ {
		attr := t.Attrs[i]
		if attr.AttrType == 0x03 {
			return attr.AttrStr
		}
	}
	return nil
}

func (t *T_Message) CheckFor(msg portal.Message, secret string) error {
	typ := t.Type()
	if t.Header.ErrCode == 0 {
		return nil
	}
	des := "未知错误"
	switch typ {
	case portal.ACK_CHALLENGE:
		switch t.Header.ErrCode {
		case 1:
			des = "请求Challenge被拒绝"
		case 2:
			des = "此链接已建立"
		case 3:
			des = "有一个用户正在认证过程中，请稍后再试"
		case 4:
			des = "此用户请求Challenge失败（发生错误）"
		}
	case portal.ACK_AUTH:
		switch t.Header.ErrCode {
		case 1:
			des = "认证请求被拒绝"
		case 2:
			des = "此链接已建立"
		case 3:
			des = "有一个用户正在认证过程中，请稍后再试"
		case 4:
			des = "此用户请求认证失败（发生错误）"
		}
	}
	return fmt.Errorf("No. %d:%s", t.Header.ErrCode, des)
}

type T_Header struct {
	Version       byte
	Type          byte //REQ_CHALLENGE,ACK_CHALLENGE,REQ_AUTH,
	Pap           byte
	Rsv           byte
	SerialNo      uint16
	ReqIdentifier uint16
	UserIp        net.IP
	UserPort      uint16
	ErrCode       byte
	AttrNum       byte
}

type T_Attr struct {
	AttrType byte
	AttrLen  byte
	AttrStr  []byte
}
