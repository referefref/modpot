#!/bin/bash

# Variables
slack_webhook_url="YOUR_SLACK_WEBHOOK_URL"

# Create a JSON payload with your message
json_payload="{\"text\": \"*Alert from Modpot:*\n- Honeypot ID: $1\n- Application: $2\n- Datetime: $3\n- IP Source: $4\n- Log Event: $5\"}"

# Use curl to send the data
curl -X POST -H "Content-type: application/json" --data "$json_payload" $slack_webhook_url
