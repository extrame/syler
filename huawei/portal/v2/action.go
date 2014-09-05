package v2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"huawei/portal"
	"net"
)

type Version struct{}

func (v *Version) NewChallenge(userip net.IP, secret string) portal.Message {
	msg := newMessage(portal.REQ_CHALLENGE, userip, portal.NewSerialNo(), 0)
	msg.AuthBy(secret)
	return msg
}

func (v *Version) NewLogout(userip net.IP, secret string) portal.Message {
	msg := newMessage(portal.REQ_LOGOUT, userip, portal.NewSerialNo(), 0)
	msg.AuthBy(secret)
	return msg
}

func (v *Version) NewAffAckAuth(userip net.IP, secret string, serial uint16, reqid uint16) portal.Message {
	msg := newMessage(portal.AFF_ACK_AUTH, userip, serial, reqid)
	msg.AuthBy(secret)
	return msg
}

func (v *Version) NewAuth(userip net.IP, secret string, username []byte, userpwd []byte, req uint16, cha []byte) portal.Message {
	msg := newMessage(3, userip, portal.NewSerialNo(), req)
	msg.Header.AttrNum = 2
	hash := md5.New()
	hash.Write([]byte{byte(req)})
	hash.Write(userpwd)
	hash.Write(cha)
	cpwd := hash.Sum(nil)
	msg.Attrs = []T_Attr{{AttrType: byte(1), AttrLen: byte(len(username)), AttrStr: username}, {AttrType: byte(4), AttrLen: byte(len(cpwd)), AttrStr: cpwd}}
	msg.AuthBy(secret)
	return msg
}

func (v *Version) IsResponse(mesg portal.Message) bool {
	switch mesg.Type() {
	case 2, 4, 6, 10:
		return true
	}
	return false
}

func (v *Version) Unmarshall(bts []byte) portal.Message {
	msg := new(T_Message)
	buf := bytes.NewBuffer(bts)
	var ipbts [4]byte
	binary.Read(buf, binary.BigEndian, &msg.Header.Version)
	binary.Read(buf, binary.BigEndian, &msg.Header.Type)
	binary.Read(buf, binary.BigEndian, &msg.Header.Pap)
	binary.Read(buf, binary.BigEndian, &msg.Header.Rsv)
	binary.Read(buf, binary.BigEndian, &msg.Header.SerialNo)
	binary.Read(buf, binary.BigEndian, &msg.Header.ReqIdentifier)
	for i := 0; i < 4; i++ {
		binary.Read(buf, binary.BigEndian, &ipbts[i])
	}
	msg.Header.UserIp = net.IPv4(ipbts[0], ipbts[1], ipbts[2], ipbts[3]).To4()
	binary.Read(buf, binary.BigEndian, &msg.Header.UserPort)
	binary.Read(buf, binary.BigEndian, &msg.Header.ErrCode)
	binary.Read(buf, binary.BigEndian, &msg.Header.AttrNum)
	var auth [16]byte
	binary.Read(buf, binary.BigEndian, &auth)
	msg.Header.Authenticator = auth[:]
	msg.Attrs = make([]T_Attr, msg.Header.AttrNum)
	for i := byte(0); i < msg.Header.AttrNum; i++ {
		attr := &msg.Attrs[i]
		binary.Read(buf, binary.BigEndian, &attr.AttrType)
		binary.Read(buf, binary.BigEndian, &attr.AttrLen)
		attr.AttrLen = attr.AttrLen - 2
		attr.AttrStr = make([]byte, attr.AttrLen)
		binary.Read(buf, binary.BigEndian, &attr.AttrStr)
	}
	return msg
}

var expect chan *T_Message
var timeout = fmt.Errorf("请求超时")

func newMessage(typ byte, userip net.IP, serialNo uint16, reqId uint16) *T_Message {
	msg := new(T_Message)
	msg.Header.Version = 0x02
	msg.Header.Type = typ
	msg.Header.SerialNo = serialNo
	msg.Header.ReqIdentifier = reqId
	msg.Header.UserIp = userip.To4()
	msg.Header.Authenticator = make([]byte, 16)
	return msg
}

// func Challenge(userip net.IP, secret string, basip net.IP) (response *T_Message, err error) {
// 	expect = make(chan *T_Message)
// 	cha := NewChallenge(userip, secret)
// 	go func() {
// 		err := cha.SendTo(basip, 2000)
// 		fmt.Println(err)
// 	}()
// 	//send challenge
// 	//expect res
// 	select {
// 	case res := <-expect:
// 		return res, res.CheckFor(ACK_CHALLENGE, cha.Header.Authenticator, secret)
// 	case <-time.After(15 * time.Second):
// 		return nil, timeout
// 	}
// }

// func Auth(userip net.IP, secret string, basip net.IP, username string, userpwd string, req uint16) (err error) {
// 	var res *T_Message
// 	res, err = Challenge(userip, secret, basip)
// 	if err == nil {
// 		cha := NewAuth(userip, secret, []byte(username), []byte(userpwd), res.Header.ReqId)
// 		go cha.SendTo(basip, 2000)
// 		//send challenge
// 		//expect res
// 		select {
// 		case res := <-expect:
// 			return res.CheckFor(ACK_AUTH, cha.Header.Authenticator, secret)
// 		case <-time.After(15 * time.Second):
// 			return timeout
// 		}
// 	} else {
// 		return
// 	}
// }
