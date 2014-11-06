package component

import (
	"fmt"
	toml "github.com/extrame/go-toml-config"
	"github.com/extrame/syler/config"
	"github.com/extrame/syler/i"
	"github.com/go-xorm/xorm"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

type DbAuthServer struct {
	engine *xorm.Engine
	DbType *string
	DbName *string
	DbUser *string
	DbPwd  *string
	DbHost *string
	DbPort *int
}

type User struct {
	Name     string
	Password string
	Mac      string
}

var NOSUCHUSER = fmt.Errorf("No such user")

func (a *DbAuthServer) AuthChap(username []byte, chapid byte, chappwd, chapcha []byte, userip net.IP) (err error, to uint32) {
	bean := new(User)
	var got = false
	if got, err = a.engine.Where("name = ?", username).Get(bean); err == nil {
		if got && i.TestChapPwd(chapid, []byte(bean.Password), chapcha, chappwd) {
			return
		} else {
			return NOSUCHUSER, 0
		}
	}
	return
}

func (a *DbAuthServer) AuthMac(mac []byte, userip net.IP) (error, uint32) {
	return fmt.Errorf("unsupported mac auth on %s", userip.String()), 0
}

func (a *DbAuthServer) AuthPap(username, userpwd []byte, userip net.IP) (err error, to uint32) {
	bean := new(User)
	var got = false
	if got, err = a.engine.Where("name = ? and password = ?", string(username), string(userpwd)).Get(bean); err == nil {
		if got {
			return
		} else {
			return NOSUCHUSER, 0
		}
	}
	fmt.Println(got, err)
	return
}

func (a *DbAuthServer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var err error
	if config.IsValidClient(r.RemoteAddr) {
		timeout := r.FormValue("timeout")
		nas := r.FormValue("nasip")
		userip_str := r.FormValue("userip")
		username := []byte(r.FormValue("username"))
		userpwd := []byte(r.FormValue("userpwd"))
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
					log.Println("username len = 0")

					w.WriteHeader(http.StatusBadRequest)
					return
				} else {
					username = []byte(string(username) + "@" + *config.HuaweiDomain)
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
}

func (a *DbAuthServer) AddConfig() {
	a.DbHost = toml.String("db.host", "localhost")
	a.DbName = toml.String("db.name", "syler")
	a.DbUser = toml.String("db.user", "syler")
	a.DbPwd = toml.String("db.password", "syler")
	a.DbType = toml.String("db.type", "mysql")
	a.DbPort = toml.Int("db.port", 3306)
}

func (a *DbAuthServer) IsConfigValid() bool {
	if *a.DbType == "sqlite3" {
		if info, err := os.Stat(*a.DbHost); err == nil {
			if info.IsDir() {
				fmt.Println("sqlite3引擎需要设置db.host参数为一个可读写文件")
				return false
			}
		}
	}
	var err error
	if a.engine, err = newDB(*a.DbType, *a.DbUser, *a.DbPwd, *a.DbHost, *a.DbName, *a.DbPort); err != nil {
		fmt.Println(err)
		return false
	}
	if err = a.engine.Sync2(new(User)); err != nil {
		fmt.Println(err)
	}
	return true
}

func NewDbAuthService() *DbAuthServer {
	return new(DbAuthServer)
}

func newDB(engine, user, pwd, host, name string, port int) (*xorm.Engine, error) {
	var q string
	if engine == "mysql" {
		q = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8", user, pwd, host, port, name)
	} else if engine == "sqlite3" {
		q = host
	}
	return xorm.NewEngine(engine, q)
}
