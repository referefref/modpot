package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func server(configs *AppConfig) {
	var wg sync.WaitGroup

	gin.SetMode(gin.ReleaseMode)

	globalRouter := gin.New()
	globalRouter.Use(gin.Logger(), gin.Recovery())

	globalRouter.Static("/css", "./web/css")
	globalRouter.Static("/scripts", "./web/scripts")
	globalRouter.StaticFile("/manage", "./web/manage.html")

	RegisterAPIRoutes(globalRouter)

	globalRouter.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/manage")
	})

	go func() {
		fmt.Println("Serving management interface on http://localhost:1337/manage")
		if err := globalRouter.Run(":1337"); err != nil {
			logError(fmt.Sprintf("Failed to serve management interface: %v", err))
		}
	}()

	for _, config := range configs.Honeypots {
		if !config.Enabled {
			continue
		}
		wg.Add(1)
		go func(config HoneypotConfig) {
			defer wg.Done()

			router := gin.New()
			router.Use(gin.Logger(), gin.Recovery())

			router.Use(func(c *gin.Context) {
				var bodyBytes []byte
				if c.Request.Body != nil {
					bodyBytes, _ = ioutil.ReadAll(c.Request.Body)
					c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
				}

				c.Next()

				requestData := c.Request.RequestURI + " " + string(bodyBytes)
				regexMatch := "no"
				if matched, _ := regexp.MatchString(config.RequestRegex, requestData); matched {
					regexMatch = "yes"
				}

				logEvent := fmt.Sprintf("Method: %s, Path: %s, Agent: %s, Body: %s", c.Request.Method, c.Request.URL.Path, c.Request.UserAgent(), string(bodyBytes))
				datetime := time.Now().Format(time.RFC3339)
				err := InsertHoneypotLog(&HoneypotLog{
					HoneypotID:    config.ID,
					Port:          config.Port,
					Datetime:      datetime,
					IPSource:      c.ClientIP(),
					IPDestination: c.Request.Host,
					LogEvent:      logEvent,
					RegexMatch:    regexMatch,
				})
				if err != nil {
					logError("Failed to insert log: " + err.Error())
				}
			})

			filePath := filepath.Join("templates", config.TemplateHTMLFile)
			router.GET(config.DetectionEndpoint, func(c *gin.Context) {
				c.File(filePath)
			})

			router.POST(config.DetectionEndpoint, func(c *gin.Context) {
				if config.RedirectURL != "" {
					c.Redirect(http.StatusFound, config.RedirectURL)
				} else {
					c.Redirect(http.StatusFound, config.DetectionEndpoint)
				}
			})

			port := fmt.Sprintf(":%d", config.Port)
			fmt.Printf("Starting server for %s on port %s\n", config.Name, port)
			if err := router.Run(port); err != nil {
				logError(fmt.Sprintf("Failed to start server for %s on port %s: %v", config.Name, port, err))
			}
		}(config)
	}

	wg.Wait()
}
