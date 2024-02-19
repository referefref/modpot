package main

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"net/http"
	"strconv"
)

var db *sql.DB

type HoneypotConfig struct {
	ID                int    `yaml:"id"`
	Name              string `yaml:"name"`
	CVE               string `yaml:"cve"`
	Application       string `yaml:"application"`
	Port              int    `yaml:"port"`
	TemplateHTMLFile  string `yaml:"template_html_file"`
	DetectionEndpoint string `yaml:"detection_endpoint"`
	RequestRegex      string `yaml:"request_regex"`
	DateCreated       string `yaml:"date_created"`
	DateUpdated       string `yaml:"date_updated"`
	RedirectURL	  string `yaml:"redirect_url"`
	Enabled           bool   `yaml:"enabled"`
}

func InitDB(filepath string) {
	var err error
	db, err = sql.Open("sqlite3", filepath)
	if err != nil {
		logError("Failed to open database: " + err.Error())
		return
	}
	logInfo("Database opened successfully")

	createTable := `
	CREATE TABLE IF NOT EXISTS honeypots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		cve TEXT,
		application TEXT,
		port INTEGER,
		template_html_file TEXT,
		detection_endpoint TEXT,
		request_regex TEXT,
		date_created TEXT,
		date_updated TEXT,
		redirect_url TEXT,
		enabled BOOLEAN DEFAULT true
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		logError("Failed to create honeypots table: " + err.Error())
		return
	}
	logInfo("Honeypots table created or already exists")

	createLogsTable := `
	CREATE TABLE IF NOT EXISTS honeypot_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		honeypotID INTEGER,
		port INTEGER,
		datetime TEXT,
		ip_source TEXT,
		ip_destination TEXT,
		log_event TEXT,
		regex_match TEXT,
		FOREIGN KEY(honeypotID) REFERENCES honeypots(id)
	);`

	_, err = db.Exec(createLogsTable)
	if err != nil {
		logError("Failed to create honeypot_logs table: " + err.Error())
		return
	}
	logInfo("Honeypot_logs table created or already exists")
}

func InsertHoneypotConfig(config *HoneypotConfig) error {
    insertSQL := `INSERT INTO honeypots(name, cve, application, port, template_html_file, detection_endpoint, request_regex, date_created, date_updated, redirect_url, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

    var redirectURL sql.NullString
    if config.RedirectURL != "" {
        redirectURL = sql.NullString{String: config.RedirectURL, Valid: true}
    } else {
        redirectURL = sql.NullString{Valid: false}
    }

    _, err := db.Exec(insertSQL, config.Name, config.CVE, config.Application, config.Port, config.TemplateHTMLFile, config.DetectionEndpoint, config.RequestRegex, config.DateCreated, config.DateUpdated, redirectURL, config.Enabled)
    if err != nil {
        logError("Failed to insert config: " + err.Error())
        return err
    }
    logInfo(fmt.Sprintf("Config '%s' inserted successfully", config.Name))
    return nil
}

func SelectHoneypotConfig(id int) (*HoneypotConfig, error) {
    config := &HoneypotConfig{}
    var redirectURLPtr *string

    query := `SELECT id, name, cve, application, port, template_html_file, detection_endpoint, request_regex, date_created, date_updated, redirect_url, enabled FROM honeypots WHERE id = ?`
    err := db.QueryRow(query, id).Scan(
        &config.ID,
        &config.Name,
        &config.CVE,
        &config.Application,
        &config.Port,
        &config.TemplateHTMLFile,
        &config.DetectionEndpoint,
        &config.RequestRegex,
        &config.DateCreated,
        &config.DateUpdated,
        &redirectURLPtr,
        &config.Enabled,
    )

    if err != nil {
        if err == sql.ErrNoRows {
            logInfo(fmt.Sprintf("Honeypot configuration for ID %d not found in database, inserting.", id))
            return nil, nil
        } else {
            logError(fmt.Sprintf("Failed to select config for ID %d: %s", id, err.Error()))
            return nil, err
        }
    }

    if redirectURLPtr != nil {
        config.RedirectURL = *redirectURLPtr
        logInfo(fmt.Sprintf("Redirect URL for config ID %d is '%s'", id, config.RedirectURL))
    } else {
        config.RedirectURL = ""
        logInfo(fmt.Sprintf("Redirect URL for config ID %d is NULL or empty", id))
    }

    logInfo(fmt.Sprintf("Successfully selected config: %s (ID %d)", config.Name, config.ID))
    return config, nil
}

func UpdateHoneypotConfig(config *HoneypotConfig) error {
	updateSQL := `UPDATE honeypots SET name = ?, cve = ?, application = ?, port = ?, template_html_file = ?, detection_endpoint = ?, request_regex = ?, date_created = ?, date_updated = ?, enabled = ? WHERE id = ?`
	statement, err := db.Prepare(updateSQL)
	if err != nil {
		logError("Failed to prepare config update: " + err.Error())
		return err
	}

	_, err = statement.Exec(config.Name, config.CVE, config.Application, config.Port, config.TemplateHTMLFile, config.DetectionEndpoint, config.RequestRegex, config.DateCreated, config.DateUpdated, config.Enabled, config.ID)
	if err != nil {
		logError("Failed to update config: " + err.Error())
		return err
	}
	logInfo(fmt.Sprintf("Config '%s' updated successfully", config.Name))
	return nil
}

func DeleteHoneypotConfig(id int) error {
	deleteSQL := `DELETE FROM honeypots WHERE id = ?`
	statement, err := db.Prepare(deleteSQL)
	if err != nil {
		logError("Failed to prepare config deletion: " + err.Error())
		return err
	}
	_, err = statement.Exec(id)
	if err != nil {
		logError("Failed to delete config: " + err.Error())
		return err
	}
	logInfo(fmt.Sprintf("Config with ID %d deleted successfully", id))
	return nil
}

type HoneypotLog struct {
	ID            int
	HoneypotID    int
	Port          int
	Datetime      string
	IPSource      string
	IPDestination string
	LogEvent      string
	RegexMatch    string `json:"regex_match"`
}

func InsertHoneypotLog(log *HoneypotLog) error {
	insertSQL := `INSERT INTO honeypot_logs(honeypotID, port, datetime, ip_source, ip_destination, log_event, regex_match) VALUES (?, ?, ?, ?, ?, ?, ?)`
	statement, err := db.Prepare(insertSQL)
	if err != nil {
		logError("Failed to prepare log insertion: " + err.Error())
		return err
	}
	_, err = statement.Exec(log.HoneypotID, log.Port, log.Datetime, log.IPSource, log.IPDestination, log.LogEvent, log.RegexMatch)
	if err != nil {
		logError("Failed to insert log: " + err.Error())
		return err
	}
	logInfo("Log inserted successfully")
	return nil
}

func SelectHoneypotLog(honeypotID int) ([]HoneypotLog, error) {
	var logs []HoneypotLog
	query := `SELECT id, honeypotID, port, datetime, ip_source, ip_destination, log_event, regex_match FROM honeypot_logs WHERE honeypotID = ?`
	rows, err := db.Query(query, honeypotID)
	if err != nil {
		logError("Failed to query logs: " + err.Error())
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var log HoneypotLog
		if err := rows.Scan(&log.ID, &log.HoneypotID, &log.Port, &log.Datetime, &log.IPSource, &log.IPDestination, &log.LogEvent, &log.RegexMatch); err != nil {
			logError("Failed to scan log from database: " + err.Error())
			continue 
		}
		logs = append(logs, log)
	}

	if err = rows.Err(); err != nil { 
		logError("Error iterating through logs: " + err.Error())
		return nil, err
	}

	logInfo(fmt.Sprintf("Retrieved %d logs successfully", len(logs)))
	return logs, nil
}

func UpdateHoneypotLog(log *HoneypotLog) error {
	updateSQL := `UPDATE honeypot_logs SET port = ?, datetime = ?, ip_source = ?, ip_destination = ?, log_event = ?, regex_match = ? WHERE id = ?`
	statement, err := db.Prepare(updateSQL)
	if err != nil {
		logError("Failed to prepare log update: " + err.Error())
		return err
	}
	_, err = statement.Exec(log.Port, log.Datetime, log.IPSource, log.IPDestination, log.LogEvent, log.RegexMatch, log.ID)
	if err != nil {
		logError("Failed to update log: " + err.Error())
		return err
	}
	logInfo(fmt.Sprintf("Log with ID %d updated successfully", log.ID))
	return nil
}

func DeleteHoneypotLog(id int) error {
	deleteSQL := `DELETE FROM honeypot_logs WHERE id = ?`
	statement, err := db.Prepare(deleteSQL)
	if err != nil {
		logError("Failed to prepare log deletion: " + err.Error())
		return err
	}
	_, err = statement.Exec(id)
	if err != nil {
		logError("Failed to delete log: " + err.Error())
		return err
	}
	logInfo(fmt.Sprintf("Log with ID %d deleted successfully", id))
	return nil
}

func RegisterAPIRoutes(router *gin.Engine) {
	logInfo("Registering API routes")
	// Honeypot configurations routes
	router.GET("/api/configs", listAllHoneypotConfigs)
	router.POST("/api/configs", insertHoneypotConfig)
	router.GET("/api/configs/:id", selectHoneypotConfig)
	router.PUT("/api/configs/:id", updateHoneypotConfig)
	router.DELETE("/api/configs/:id", deleteHoneypotConfig)
	router.PUT("/api/configs/:id/enable-disable", EnableDisableHoneypot)

	// Honeypot logs routes
	router.GET("/api/logs", listAllHoneypotLogs)
	router.POST("/api/logs", insertHoneypotLog)
	router.GET("/api/logs/:honeypotID", selectHoneypotLogs)
	router.PUT("/api/logs/:id", updateHoneypotLog)
	router.DELETE("/api/logs/:id", deleteHoneypotLog)
}

func insertHoneypotConfig(c *gin.Context) {
	var config HoneypotConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		logError("Error binding JSON for config insert: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := InsertHoneypotConfig(&config); err != nil {
		logError("Error inserting config: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Config inserted successfully: %+v", config))
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func selectHoneypotConfig(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		logError("Invalid ID for config selection: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	config, err := SelectHoneypotConfig(id)
	if err != nil {
		logError("Error selecting config: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Config selected successfully: %+v", config))
	c.JSON(http.StatusOK, config)
}

func updateHoneypotConfig(c *gin.Context) {
	var config HoneypotConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		logError("Error binding JSON for config update: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		logError("Invalid ID for config update: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	config.ID = id
	if err := UpdateHoneypotConfig(&config); err != nil {
		logError("Error updating config: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Config updated successfully: %+v", config))
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func deleteHoneypotConfig(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		logError("Invalid ID for config deletion: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := DeleteHoneypotConfig(id); err != nil {
		logError("Error deleting config: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Config with ID %d deleted successfully", id))
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func EnableDisableHoneypot(c *gin.Context) {
    id, err := strconv.Atoi(c.Param("id"))
    if err != nil {
        logError("Invalid ID: " + err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
        return
    }

    var requestBody struct {
        Enabled bool `json:"enabled"`
    }
    if err := c.ShouldBindJSON(&requestBody); err != nil {
        logError("Error binding JSON: " + err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    _, err = db.Exec("UPDATE honeypots SET enabled = ? WHERE id = ?", requestBody.Enabled, id)
    if err != nil {
        logError("Failed to update enabled state: " + err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    logInfo(fmt.Sprintf("Honeypot configuration with ID %d enabled/disabled successfully", id))
    c.JSON(http.StatusOK, gin.H{"status": "OK", "id": id, "enabled": requestBody.Enabled})
}

// Honeypot Log Handlers

func insertHoneypotLog(c *gin.Context) {
	var log HoneypotLog
	if err := c.ShouldBindJSON(&log); err != nil {
		logError("Error binding JSON for log insert: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := InsertHoneypotLog(&log); err != nil {
		logError("Error inserting log: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Log inserted successfully: %+v", log))
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func selectHoneypotLogs(c *gin.Context) {
	honeypotID, err := strconv.Atoi(c.Param("honeypotID"))
	if err != nil {
		logError("Invalid honeypot ID for log selection: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid honeypot ID"})
		return
	}

	logs, err := SelectHoneypotLog(honeypotID)
	if err != nil {
		logError("Error selecting logs: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Logs for honeypot ID %d selected successfully", honeypotID))
	c.JSON(http.StatusOK, logs)
}

func updateHoneypotLog(c *gin.Context) {
	var log HoneypotLog
	if err := c.ShouldBindJSON(&log); err != nil {
		logError("Error binding JSON for log update: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		logError("Invalid ID for log update: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	log.ID = id
	if err := UpdateHoneypotLog(&log); err != nil {
		logError("Error updating log: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Log with ID %d updated successfully", id))
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func deleteHoneypotLog(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		logError("Invalid ID for log deletion: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := DeleteHoneypotLog(id); err != nil {
		logError("Error deleting log: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logInfo(fmt.Sprintf("Log with ID %d deleted successfully", id))
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func listAllHoneypotConfigs(c *gin.Context) {
    var configs []HoneypotConfig
    query := "SELECT id, name, cve, application, port, template_html_file, detection_endpoint, request_regex, date_created, date_updated, redirect_url, enabled FROM honeypots"
    rows, err := db.Query(query)
    if err != nil {
        logError("Failed to query database for configs: " + err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query database for configs"})
        return
    }
    defer rows.Close()

    for rows.Next() {
        var config HoneypotConfig
        if err := rows.Scan(&config.ID, &config.Name, &config.CVE, &config.Application, &config.Port, &config.TemplateHTMLFile, &config.DetectionEndpoint, &config.RequestRegex, &config.DateCreated, &config.DateUpdated, &config.RedirectURL, &config.Enabled); err != nil {
            logError("Failed to scan config from database: " + err.Error())
            continue
        }
        configs = append(configs, config)
    }

    if err = rows.Err(); err != nil {
        logError("Error iterating through configs: " + err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error iterating through configs"})
        return
    }

    logInfo(fmt.Sprintf("Total %d configs listed successfully", len(configs)))
    c.JSON(http.StatusOK, configs)
}

func listAllHoneypotLogs(c *gin.Context) {
    var logs []HoneypotLog
    query := "SELECT id, honeypotID, port, datetime, ip_source, ip_destination, log_event, regex_match FROM honeypot_logs"
    rows, err := db.Query(query)
    if err != nil {
        logError("Failed to query database for logs: " + err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query database for logs"})
        return
    }
    defer rows.Close()

    for rows.Next() {
        var log HoneypotLog
        if err := rows.Scan(&log.ID, &log.HoneypotID, &log.Port, &log.Datetime, &log.IPSource, &log.IPDestination, &log.LogEvent, &log.RegexMatch); err != nil {
            logError("Failed to scan log from database: " + err.Error())
            continue
        }
        logs = append(logs, log)
    }

    if err = rows.Err(); err != nil {
        logError("Error iterating through logs: " + err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error iterating through logs"})
        return
    }

    logInfo(fmt.Sprintf("Total %d logs listed successfully", len(logs)))
    c.JSON(http.StatusOK, logs)
}
