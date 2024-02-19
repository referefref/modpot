package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

func ValidateHoneypotConfigs(configs []HoneypotConfig) ([]HoneypotConfig, error) {
	var validConfigs []HoneypotConfig
	logInfo("Starting validation of honeypot configurations")

	for _, config := range configs {
		logInfo(fmt.Sprintf("Validating configuration: %s", config.Name))
		if err := validateHoneypotConfig(config); err != nil {
			logError(fmt.Sprintf("Validation error for '%s': %v", config.Name, err))
			continue
		}
		logSuccess(fmt.Sprintf("Configuration validated successfully: %s", config.Name))
		validConfigs = append(validConfigs, config)
	}

	if len(validConfigs) == 0 {
		logError("No valid honeypot configurations found")
		return nil, fmt.Errorf("no valid honeypot configurations found")
	}

	logSuccess(fmt.Sprintf("Validated %d configurations successfully", len(validConfigs)))
	return validConfigs, nil
}


func validateHoneypotConfig(config HoneypotConfig) error {
	logInfo(fmt.Sprintf("Validating individual fields for configuration: %s", config.Name))
  
	if config.ID == 0 || config.Name == "" || config.Port == 0 || config.TemplateHTMLFile == "" || config.DetectionEndpoint == "" || config.RequestRegex == "" {
		logError(fmt.Sprintf("Mandatory fields missing in configuration: %s", config.Name))
		return fmt.Errorf("mandatory fields missing in honeypot configuration for '%s'", config.Name)
	}
	logInfo(fmt.Sprintf("All mandatory fields present for '%s'", config.Name))

	if config.Port < 1 || config.Port > 65535 {
		logError(fmt.Sprintf("Port out of range for '%s': %d", config.Name, config.Port))
		return fmt.Errorf("port must be within the range 1-65535 for '%s'", config.Name)
	}
	logInfo(fmt.Sprintf("Port within valid range for '%s'", config.Name))

	templatePath := filepath.Join("templates", config.TemplateHTMLFile)
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		logError(fmt.Sprintf("Template HTML file does not exist for '%s': %s", config.Name, templatePath))
		return fmt.Errorf("template HTML file '%s' does not exist for '%s'", templatePath, config.Name)
	}
	logInfo(fmt.Sprintf("Template HTML file exists for '%s'", config.Name))

	if _, err := regexp.Compile(config.RequestRegex); err != nil {
		logError(fmt.Sprintf("Invalid request regex for '%s': %s", config.Name, config.RequestRegex))
		return fmt.Errorf("request regex '%s' is not valid for '%s'", config.RequestRegex, config.Name)
	}
	logInfo(fmt.Sprintf("Request regex is valid for '%s'", config.Name))

	logInfo(fmt.Sprintf("RedirectURL for '%s': %s", config.Name, config.RedirectURL))

	return nil
}
