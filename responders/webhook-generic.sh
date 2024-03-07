#!/bin/bash

# Variables
webhook_url="YOUR_GENERIC_WEBHOOK_URL"

# Create a JSON payload with your data
json_payload="{\"honeypot_id\": \"$1\", \"application\": \"$2\", \"datetime\": \"$3\", \"ip_source\": \"$4\", \"log_event\": \"$5\"}"

# Use curl to send the data
curl -X POST -H "Content-type: application/json" --data "$json_payload" $webhook_url
