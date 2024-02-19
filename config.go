package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type AppConfig struct {
	Honeypots []HoneypotConfig `yaml:"honeypots"`
}

func LoadConfigurations(configPath string) (*AppConfig, error) {
	logInfo("Loading configuration from YAML file: " + configPath)

	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		logError("Failed to read configuration file: " + err.Error())
		return nil, err
	}

	var appConfig AppConfig
	err = yaml.Unmarshal(configFile, &appConfig)
	if err != nil {
		logError("Failed to unmarshal YAML configuration: " + err.Error())
		return nil, err
	}

	logInfo(fmt.Sprintf("Found %d configurations in YAML file.", len(appConfig.Honeypots)))

	for _, config := range appConfig.Honeypots {
		logInfo("Processing configuration for: " + config.Name)

		if err := validateHoneypotConfig(config); err != nil {
			logError("Validation failed for " + config.Name + ": " + err.Error())
			continue
		}

		existingConfig, err := SelectHoneypotConfig(config.ID)
		if err != nil || existingConfig == nil {
			logInfo("Inserting new configuration for: " + config.Name)
			err = InsertHoneypotConfig(&config)
			if err != nil {
				logError("Failed to insert configuration for " + config.Name + ": " + err.Error())
				continue
			}
			logSuccess("Successfully inserted configuration for: " + config.Name)
		} else {
			logInfo("Updating existing configuration for: " + config.Name)
			err = UpdateHoneypotConfig(&config)
			if err != nil {
				logError("Failed to update configuration for " + config.Name + ": " + err.Error())
				continue
			}
			logSuccess("Successfully updated configuration for: " + config.Name)
		}
	}

	return &appConfig, nil
}
