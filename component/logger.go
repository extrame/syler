package component

import (
	"github.com/extrame/syler/config"
	"log"
	"os"
	"path/filepath"
)

func InitLogger() {
	if *config.LogFile != "" {
		file := filepath.FromSlash(*config.LogFile)
		lfile, err := os.OpenFile(file, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0777)
		if err != nil {
			log.Println("open log file err")
		}
		log.SetOutput(lfile)
	}
}
