package component

import (
	"log"
	"os"
	"path/filepath"
	"syler/config"
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
