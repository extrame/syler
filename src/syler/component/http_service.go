package component

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syler/config"
)

func ErrorWrap(w http.ResponseWriter) {
	if e := recover(); e != nil {
		log.Print("panic:", e, "\n", string(debug.Stack()))
		w.WriteHeader(http.StatusInternalServerError)
		if err, ok := e.(error); ok {
			w.Write([]byte(err.Error()))
		}
	}
}

func StartHttp() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			ErrorWrap(w)
		}()
		w.Header().Add("Access-Control-Allow-Origin", *config.RemoteServer)
		var err error
		if config.IsValidClient(r.RemoteAddr) {
			timeout := r.FormValue("timeout")
			nas := r.FormValue("nas")
			userip_str := r.FormValue("userip")
			username := []byte(r.FormValue("username"))
			userpwd := []byte(r.FormValue("userpwd"))
			publicKey := []byte(r.FormValue("publickey"))
			var to uint64
			to, err = strconv.ParseUint(timeout, 10, 32)

			userip := net.ParseIP(userip_str)
			if userip == nil {
				if *config.UseRemoteIpAsUserIp == true {
					ip, _, _ := net.SplitHostPort(r.RemoteAddr)
					userip = net.ParseIP(ip)
				} else {
					err = fmt.Errorf("UserIp is not available and UseRemoteIpAsUserIp is false")
				}
			}

			if userip != nil {
				if basip := net.ParseIP(nas); basip != nil {
					log.Printf("got a login request from %s on nas %s\n", userip, basip)
					if len(username) == 0 {
						if *config.RandomUser {
							username, userpwd = RandomUser(userip, basip, *config.HuaweiDomain, uint32(to))
						} else {
							w.WriteHeader(http.StatusBadRequest)
							return
						}
					} else if len(publicKey) != 0 {
						AuthingUser[userip.String()] = AuthInfo{username, userpwd, publicKey, uint32(to)}
					} else {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if err = Auth(userip, basip, uint32(to), username, userpwd); err == nil {
						w.WriteHeader(http.StatusOK)
						return
					}
				} else {
					err = fmt.Errorf("Parse Ip err from %s", nas)
				}
			}
		} else {
			err = fmt.Errorf("Not Allowed from this IP")
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			ErrorWrap(w)
		}()
		var err error
		nas := r.FormValue("nas")
		userip_str := r.FormValue("userip")
		if userip := net.ParseIP(userip_str); userip != nil {
			if basip := net.ParseIP(nas); basip != nil {
				if _, err = Logout(userip, *config.PortalSecret, basip); err == nil {
					w.WriteHeader(http.StatusOK)
					return
				}
			} else {
				err = fmt.Errorf("Parse Ip err from %s", nas)
			}
		} else {
			err = fmt.Errorf("Parse Ip err from %s", userip_str)
		}
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Show login page")
		path := filepath.FromSlash(*config.LoginPage)
		http.ServeFile(w, r, path)
	})
	log.Printf("listen http on %d\n", *config.HttpPort)
	err := http.ListenAndServe(fmt.Sprintf(":%d", *config.HttpPort), nil)
	if err != nil {
		fmt.Println(err)
		log.Println(err)
	}
}
