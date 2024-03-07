#!/bin/bash

# Variables
splunk_hec_token="YOUR_SPLUNK_HEC_TOKEN"
splunk_hec_endpoint="https://your-splunk-instance:8088/services/collector"

# Create a JSON payload with your data
json_payload="{\"event\": {\"honeypot_id\": \"$1\", \"application\": \"$2\", \"datetime\": \"$3\", \"ip_source\": \"$4\", \"log_event\": \"$5\"}}"

# Use curl to send the data
curl -k -H "Authorization: Splunk $splunk_hec_token" -H "Content-Type: application/json" -d "$json_payload" $splunk_hec_endpoint
