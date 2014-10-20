package component

import (
	"fmt"
	"github.com/extrame/syler/config"
	"github.com/extrame/syler/i"
	"log"
	"net/http"
)

func StartHttp() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			i.ErrorWrap(w)
		}()
		if handler, ok := i.ExtraAuth.(i.HttpLoginHandler); ok {
			handler.HandleLogin(w, r)
		} else {
			BASIC_SERVICE.HandleLogin(w, r)
		}
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			i.ErrorWrap(w)
		}()
		if handler, ok := i.ExtraAuth.(i.HttpLogoutHandler); ok {
			handler.HandleLogout(w, r)
		} else {
			BASIC_SERVICE.HandleLogout(w, r)
		}
	})
	if extrahttp, ok := i.ExtraAuth.(i.ExtraHttpHandler); ok {
		extrahttp.AddExtraHttp()
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			i.ErrorWrap(w)
		}()
		if handler, ok := i.ExtraAuth.(i.HttpRootHandler); ok {
			handler.HandleRoot(w, r)
		} else {
			BASIC_SERVICE.HandleRoot(w, r)
		}
	})
	log.Printf("listen http on %d\n", *config.HttpPort)
	err := http.ListenAndServe(fmt.Sprintf(":%d", *config.HttpPort), nil)
	if err != nil {
		fmt.Println(err)
		log.Println(err)
	}
}
