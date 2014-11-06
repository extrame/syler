package portal

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"time"
)

var conn *net.UDPConn
var cb_fallback func(Message, net.IP)
var Ver Version
var expect = make(map[uint16]chan Message)
var timeout = fmt.Errorf("请求超时")
var Timeout = 15

const (
	_             = iota
	REQ_CHALLENGE = iota
	ACK_CHALLENGE = iota
	REQ_AUTH      = iota
	ACK_AUTH      = iota
	REQ_LOGOUT    = iota
	ACK_LOGOUT    = iota
	AFF_ACK_AUTH  = iota
	NTF_LOGOUT    = iota
	REQ_INFO      = iota
	ACK_INFO      = iota
)

type Message interface {
	Bytes() []byte
	Type() byte
	ReqId() uint16
	SerialId() uint16
	UserIp() net.IP
	CheckFor(Message, string) error
	AttributeLen() int
	Attribute(int) Attribute
}

type Attribute interface {
	Type() byte
	Length() byte
	Byte() []byte
}

type ChallengeRes interface {
	GetChallenge() []byte
}

type Version interface {
	Unmarshall([]byte) Message
	IsResponse(Message) bool
	NewChallenge(net.IP, string) Message
	NewAuth(net.IP, string, []byte, []byte, uint16, []byte) Message
	NewAffAckAuth(net.IP, string, uint16, uint16) Message
	NewLogout(net.IP, string) Message
	NewReqInfo(net.IP, string) Message
}

func RegisterFallBack(f func(Message, net.IP)) {
	cb_fallback = f
}

func SetVersion(v Version) {
	Ver = v
}

func ListenAndService(addr string) (err error) {
	var ad *net.UDPAddr
	ad, err = net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	conn, err = net.ListenUDP("udp", ad)
	if err != nil {
		return
	}

	for {
		data := make([]byte, 4096)
		n, saddr, err := conn.ReadFromUDP(data)
		if err != nil {
			return err
		}
		go func(bts []byte) {
			message := Ver.Unmarshall(bts)
			if c, ok := expect[message.SerialId()]; ok {
				c <- message
			} else {
				log.Print("get a active message")
				cb_fallback(message, saddr.IP)
			}
		}(data[:n])
	}

	return
}

func Send(mess Message, dest net.IP, port int, secret string, sync bool) (Message, error) {
	defer func() {
		delete(expect, mess.SerialId())
	}()
	receiver, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.String(), port))
	conn.WriteTo(mess.Bytes(), receiver)
	if err != nil {
		return nil, err
	}
	if !sync {
		return nil, nil
	}
	c := make(chan Message)
	expect[mess.SerialId()] = c
	// 发送数据
	select {
	case res := <-c:
		return res, res.CheckFor(mess, secret)
	case <-time.After(time.Duration(Timeout) * time.Second):
		return nil, timeout
	}
}

func Challenge(userip net.IP, secret string, basip net.IP, basport int) (res Message, err error) {
	cha := Ver.NewChallenge(userip, secret)
	return Send(cha, basip, basport, secret, true)
}

func Logout(userip net.IP, secret string, basip net.IP, basport int) (res Message, err error) {
	cha := Ver.NewLogout(userip, secret)
	return Send(cha, basip, basport, secret, true)
}

func ChapAuth(userip net.IP, secret string, basip net.IP, basport int, username, userpwd []byte, reqid uint16, cha []byte) (res Message, err error) {
	auth := Ver.NewAuth(userip, secret, username, userpwd, reqid, cha)
	return Send(auth, basip, basport, secret, true)
}

func AffAckAuth(userip net.IP, secret string, basip net.IP, basport int, serial uint16, reqid uint16) (Message, error) {
	AffAckAuth := Ver.NewAffAckAuth(userip, secret, serial, reqid)
	return Send(AffAckAuth, basip, basport, secret, false)
}

func ReqInfo(userip net.IP, secret string, basip net.IP, basport int) (Message, error) {
	ReqInfo := Ver.NewReqInfo(userip, secret)
	return Send(ReqInfo, basip, basport, secret, true)
}

func NewSerialNo() uint16 {
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(math.MaxUint16)
	return uint16(r)
}
