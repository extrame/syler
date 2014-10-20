package v1

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"github.com/extrame/syler/huawei/portal"
	"net"
)

type Version struct{}

func (v *Version) NewChallenge(userip net.IP, secret string) portal.Message {
	return newMessage(portal.REQ_CHALLENGE, userip, secret, portal.NewSerialNo(), 0)
}

func (v *Version) NewLogout(userip net.IP, secret string) portal.Message {
	return newMessage(portal.REQ_LOGOUT, userip, secret, portal.NewSerialNo(), 0)
}

func (v *Version) NewAffAckAuth(userip net.IP, secret string, serial uint16, reqid uint16) portal.Message {
	return newMessage(portal.AFF_ACK_AUTH, userip, secret, serial, reqid)
}

func (v *Version) NewReqInfo(userip net.IP, secret string) portal.Message {
	msg := newMessage(portal.REQ_INFO, userip, secret, portal.NewSerialNo(), 0)
	msg.Header.AttrNum = 2
	msg.Attrs = []T_Attr{{AttrType: byte(6), AttrLen: 0}, {AttrType: byte(7), AttrLen: 0}}
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
	// var auth [16]byte
	// binary.Read(buf, binary.BigEndian, &auth)
	// msg.Header.Authenticator = auth[:]
	msg.Attrs = make([]T_Attr, msg.Header.AttrNum)
	for i := byte(0); i < msg.Header.AttrNum; i++ {
		attr := &msg.Attrs[i]
		binary.Read(buf, binary.BigEndian, &attr.AttrType)
		binary.Read(buf, binary.BigEndian, &attr.AttrLen)
		attr.AttrStr = make([]byte, attr.AttrLen-2)
		binary.Read(buf, binary.BigEndian, &attr.AttrStr)
	}
	return msg
}

func newMessage(typ byte, userip net.IP, secret string, serialNo uint16, reqId uint16) *T_Message {
	msg := new(T_Message)
	msg.Header.Version = 0x01
	msg.Header.Type = typ
	msg.Header.SerialNo = serialNo
	msg.Header.ReqIdentifier = reqId
	msg.Header.UserIp = userip.To4()
	return msg
}

func (v *Version) NewAuth(userip net.IP, secret string, username []byte, userpwd []byte, req uint16, cha []byte) portal.Message {
	msg := newMessage(3, userip, secret, portal.NewSerialNo(), req)
	msg.Header.AttrNum = 3
	hash := md5.New()
	hash.Write([]byte{byte(req)})
	hash.Write(userpwd)
	hash.Write(cha)
	cpwd := hash.Sum(nil)
	msg.Attrs = []T_Attr{
		{AttrType: byte(1), AttrLen: byte(len(username)), AttrStr: username},
		{AttrType: byte(3), AttrLen: byte(len(cha)), AttrStr: cha},
		{AttrType: byte(4), AttrLen: byte(len(cpwd)), AttrStr: cpwd},
	}
	return msg
}
