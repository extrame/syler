package component

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"github.com/extrame/radius"
	"log"
	"net"
	"syler/config"
)

func StartRadiusAuth() {
	log.Printf("listening auth on %d\n", *config.RadiusAuthPort)
	s := radius.NewServer(fmt.Sprintf(":%d", *config.RadiusAuthPort), *config.RadiusSecret)
	s.RegisterService(&AuthService{})
	err := s.ListenAndServe()
	log.Println(err)
}

func StartRadiusAcc() {
	if *config.RadiusAccPort != *config.RadiusAuthPort {
		log.Printf("listening acc on %d\n", *config.RadiusAccPort)
		s := radius.NewServer(fmt.Sprintf(":%d", *config.RadiusAccPort), *config.RadiusSecret)
		s.RegisterService(&AccService{})
		err := s.ListenAndServe()
		log.Println(err)
	}
}

type AuthService struct{}

func (p *AuthService) Authenticate(request *radius.Packet) (*radius.Packet, error) {
	var username, userpwd []byte
	var chapid byte
	var chappwd []byte
	var chapmod = false
	var chapcha = request.Authenticator[:]
	var userip net.IP

	if request.Code == radius.AccountingRequest {
		npac := request.Reply()
		npac.Code = radius.AccountingResponse
		npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("ok!")})
		return npac, nil
	}

	for _, v := range request.AVPs {
		if v.Type == radius.UserName {
			username = v.Value
		} else if v.Type == radius.UserPassword {
			userpwd = v.Value
		} else if v.Type == radius.CHAPPassword {
			chapmod = true
			chapid = v.Value[0]
			chappwd = v.Value[1:]
		} else if v.Type == radius.CHAPChallenge {
			chapcha = v.Value
		} else if v.Type == radius.FramedIPAddress {
			userip = net.IPv4(v.Value[0], v.Value[1], v.Value[2], v.Value[3])
		}
	}
	npac := request.Reply()
	msg := "ok!"
	success := false
	var info AuthInfo
	var ok bool
	if info, ok = AuthingUser[userip.String()]; ok {
		if chapmod && bytes.Compare(username, info.Name) == 0 {
			hash := md5.New()
			hash.Write([]byte{chapid})
			hash.Write(info.Pwd)
			hash.Write(chapcha)
			tested := hash.Sum(nil)
			for i := 0; i < len(tested); i++ {
				if tested[i] != chappwd[i] {
					success = false
					log.Println("radius auth - incorrect password of ", userip.String())
				}
			}
			success = true
		} else if bytes.Compare(info.Pwd, userpwd) == 0 {
			success = true
		}
	} else {
		log.Println("radius auth - no such user ", userip.String())
	}
	if success {
		if info.Timeout != 0 {
			var to_bts = make([]byte, 4)
			binary.BigEndian.PutUint32(to_bts, info.Timeout)
			npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.SessionTimeout, Value: to_bts})
		}
		npac.Code = radius.AccessAccept
	} else {
		npac.Code = radius.AccessReject
		msg = "no such user!"
	}
	npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte(msg)})

	return npac, nil
}

type AccService struct{}

func (p *AccService) Authenticate(request *radius.Packet) (*radius.Packet, error) {
	npac := request.Reply()
	npac.Code = radius.AccountingResponse
	npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("ok!")})
	return npac, nil
}
