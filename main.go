package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	configPath string
	configs    *AppConfig
	dbPath     string
	verbose    bool
	refreshDB  bool
)

func init() {
	flag.StringVar(&configPath, "config", "config.yaml", "Path to the configuration file")
	flag.StringVar(&dbPath, "db", "honeypot.db", "Path to the SQLite database file")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&refreshDB, "refresh-db", false, "Refresh the database (Warning: This will delete existing data!)")

	flag.Parse()

	InitializeLogger()

	if verbose {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
}

func main() {
	if verbose {
		fmt.Println("Starting the honeypot server...")
	}

	if refreshDB {
		if verbose {
			fmt.Println("Refreshing database...")
		}
		os.Remove(dbPath)
	}

	InitDB(dbPath)

	configs, err := LoadConfigurations(configPath)
	if err != nil {
		logError("Failed to load configurations: " + err.Error())
		return
	}
	server(configs)
}
