package component

import (
	"encoding/binary"
	"fmt"
	"github.com/extrame/radius"
	"log"
	"net"
	"syler/config"
	"syler/i"
)

var CommonPapAuth i.PapAuthService
var CommonChapAuth i.ChapAuthService

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
	var err error
	var timeout uint32
	if chapmod {
		if auth, ok := i.ExtraAuth.(i.ChapAuthService); ok {
			err, timeout = auth.AuthChap(username, chapid, chappwd, chapcha, userip)
		} else {
			err, timeout = CommonChapAuth.AuthChap(username, chapid, chappwd, chapcha, userip)
		}
	} else {
		if auth, ok := i.ExtraAuth.(i.PapAuthService); ok {
			err, timeout = auth.AuthPap(username, userpwd, userip)
		} else {
			err, timeout = CommonPapAuth.AuthPap(username, userpwd, userip)
		}
	}

	if err == nil {
		if timeout != 0 {
			var to_bts = make([]byte, 4)
			binary.BigEndian.PutUint32(to_bts, timeout)
			npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.SessionTimeout, Value: to_bts})
		}
		npac.Code = radius.AccessAccept
	} else {
		npac.Code = radius.AccessReject
		msg = err.Error()
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
