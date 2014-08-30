package component

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"syler/config"
	"syler/i"
)

var CommonHttpHandler i.HttpHandler

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
		if handler, ok := i.ExtraAuth.(i.HttpHandler); ok {
			handler.HandleLogin(w, r)
		} else {

		}
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			ErrorWrap(w)
		}()
		var err error
		nas := r.FormValue("nas") //TODO
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
