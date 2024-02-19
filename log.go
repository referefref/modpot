package main

import (
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"time"
)

var log = logrus.New()

func InitializeLogger() {
	log.Out = os.Stdout                       
	log.SetFormatter(&logrus.JSONFormatter{})
}


func LogRequest(request *http.Request) {
    fullPath := request.URL.Path
    if queryString := request.URL.RawQuery; queryString != "" {
        fullPath += "?" + queryString
    }

    log.WithFields(logrus.Fields{
        "time":            time.Now().Format(time.RFC3339),
        "source_ip":       request.RemoteAddr,
        "method":          request.Method,
        "uri":             fullPath,
        "user_agent":      request.UserAgent(),
        "x_forwarded_for": request.Header.Get("X-Forwarded-For"),
    }).Info("Honeypot interaction detected")
}

func LogEvent(level logrus.Level, message string, fields map[string]interface{}) {
	if fields != nil {
		log.WithFields(fields).Log(level, message)
	} else {
		log.Log(level, message)
	}
}

func LogError(err error) {
	log.WithFields(logrus.Fields{
		"time": time.Now().Format(time.RFC3339),
	}).Error(err)
}

func logError(message string) {
	fmt.Println(color.Ize(color.Red, "Error: "+message))
}

func logInfo(message string) {
	fmt.Println(color.Ize(color.Cyan, "INFO: "+message))
}

func logSuccess(message string) {
	fmt.Println(color.Ize(color.Green, "SUCCESS: "+message))
}
