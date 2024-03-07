package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
				logID, err := InsertHoneypotLog(&HoneypotLog{
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
				} else if regexMatch == "yes" {
					logInfo(fmt.Sprintf("Calling triggerResponder with log ID: %d", logID))
					go func() {
					if err := triggerResponder(logID); err != nil {
						fmt.Sprintf("Error: %s", err)
					}
				}()
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

func getParameterValue(placeholder string, config *HoneypotConfig, log *HoneypotLog) (string, error) {
    switch placeholder {
    case "honeypots.id":
        return strconv.Itoa(config.ID), nil
    case "honeypots.application":
        return config.Application, nil
    case "honeypot_logs.datetime":
        return log.Datetime, nil
    case "honeypot_logs.ip_source":
        return log.IPSource, nil
    case "honeypot_logs.log_event":
        return log.LogEvent, nil
    default:
        errMsg := fmt.Sprintf("Unknown parameter placeholder: %s", placeholder)
        logError(errMsg)
        return "", fmt.Errorf(errMsg)
    }
}
func triggerResponder(logID int64) error {
    logEntry, err := SelectHoneypotLogByID(logID)
    if err != nil {
        logError(fmt.Sprintf("Failed to fetch log entry: %v", err))
        return fmt.Errorf("failed to fetch log entry: %w", err)
    }

    config, err := SelectHoneypotConfig(logEntry.HoneypotID)
    if err != nil {
        logError(fmt.Sprintf("Failed to select honeypot config: %v", err))
        return fmt.Errorf("failed to select honeypot config: %w", err)
    }

    for _, responder := range config.Responders {
        var cmdArgs []string
        cmdArgs = append(cmdArgs, responder.Script)

        for _, param := range responder.Parameters {
            value, err := getParameterValue(param, config, logEntry)
            if err != nil {
                logError(fmt.Sprintf("Failed to get parameter value: %v", err))
                return fmt.Errorf("failed to get parameter value for %s: %w", param, err)
            }
            cmdArgs = append(cmdArgs, value)
        }

        logInfo(fmt.Sprintf("Preparing to execute command: %s %s", responder.Engine, strings.Join(cmdArgs, " ")))

        cmd := exec.Command(responder.Engine, cmdArgs...)
        cmd.Dir = "./responders/"
        var out, stderr bytes.Buffer
        cmd.Stdout = &out
        cmd.Stderr = &stderr

        logInfo(fmt.Sprintf("Executing responder: %s %s", responder.Engine, strings.Join(cmdArgs, " ")))
        if err := cmd.Run(); err != nil {
            logError(fmt.Sprintf("Responder script execution failed: %v. Stderr: %s", err, stderr.String()))
            return fmt.Errorf("responder script execution failed: %w. Stderr: %s", err, stderr.String())
        }
        logInfo(fmt.Sprintf("Responder executed successfully. Output:\n%s", out.String()))
    }

    return nil
}
