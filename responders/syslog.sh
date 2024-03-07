#!/bin/bash

# Variables
syslog_server="syslog_server_address"
syslog_port="514"

# Create a log message
log_message="<14>$1 $2 $3 $4 $5"

# Send the log message using nc (netcat)
echo "$log_message" | nc -w1 -u $syslog_server $syslog_port
