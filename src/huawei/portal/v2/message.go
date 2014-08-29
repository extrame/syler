package v2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"huawei/portal"
	"log"
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

func (t *T_Message) Type() byte {
	return t.Header.Type
}

func (t *T_Message) AuthBy(secret string) {
	hashMd5 := md5.New()
	hashMd5.Write(t.Bytes())
	hashMd5.Write([]byte(secret))

	t.Header.Authenticator = hashMd5.Sum(nil)
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
	binary.Write(buf, binary.BigEndian, msg.Header.Authenticator)
	for _, v := range msg.Attrs {
		binary.Write(buf, binary.BigEndian, v.AttrType)
		binary.Write(buf, binary.BigEndian, v.AttrLen+2)
		binary.Write(buf, binary.BigEndian, v.AttrStr)
	}
	return buf.Bytes()
}

// func Unmarshall(bts []byte) *T_Message {
// 	msg := new(T_Message)
// 	buf := bytes.NewBuffer(bts)
// 	var ipbts [4]byte
// 	binary.Read(buf, binary.BigEndian, &msg.Header.Version)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.Type)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.Pap)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.Rsv)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.SerialNo)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.ReqIdentifier)
// 	for i := 0; i < 4; i++ {
// 		binary.Read(buf, binary.BigEndian, &ipbts[i])
// 	}
// 	msg.Header.UserIp = net.IPv4(ipbts[0], ipbts[1], ipbts[2], ipbts[3]).To4()
// 	binary.Read(buf, binary.BigEndian, &msg.Header.UserPort)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.ErrCode)
// 	binary.Read(buf, binary.BigEndian, &msg.Header.AttrNum)
// 	var auth [16]byte
// 	binary.Read(buf, binary.BigEndian, &auth)
// 	msg.Header.Authenticator = auth[:]
// 	msg.Attrs = make([]T_Attr, msg.Header.AttrNum)
// 	for i := byte(0); i < msg.Header.AttrNum; i++ {
// 		attr := &msg.Attrs[i]
// 		binary.Read(buf, binary.BigEndian, &attr.AttrType)
// 		binary.Read(buf, binary.BigEndian, &attr.AttrLen)
// 		binary.Read(buf, binary.BigEndian, &attr.AttrStr)
// 	}
// 	return msg
// }

// func (t *T_Message) SendTo(dest net.IP, port int) (err error) {
// 	addr, err := net.ResolveUDPAddr("udp", ":50100")
// 	if err != nil {
// 		return err
// 	}
// 	conn, err := net.ListenUDP("udp", addr)
// 	if err != nil {
// 		return err
// 	}
// 	defer conn.Close()
// 	receiver, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.String(), port))
// 	// 发送数据
// 	conn.WriteTo(t.Bytes(), receiver)
// 	if err != nil {
// 		return err
// 	}

// 	// 接收数据 TODO timeout
// 	data := make([]byte, 4096)
// 	_, _, err = conn.ReadFromUDP(data)
// 	if err != nil {
// 		return
// 	}
// 	expect <- Unmarshall(data)
// 	return
// }

func (t *T_Message) CheckFor(req portal.Message, secret string) error {
	msg := req.(*T_Message)
	auth := msg.Header.Authenticator
	typ := req.Type()
	if t.Header.ErrCode == 0 {
		return nil
	}
	des := "未知错误"
	wanted := t.Header.Authenticator
	t.Header.Authenticator = auth
	t.AuthBy(secret)
	for k, v := range wanted {
		if v != t.Header.Authenticator[k] {
			log.Printf("md5 error of message by secret : %s on auth %x\n", secret, t.Header.Authenticator)
			return fmt.Errorf("MD5鉴权错误")
		}
	}
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
	Authenticator []byte
}

type T_Attr struct {
	AttrType byte
	AttrLen  byte
	AttrStr  []byte
}
