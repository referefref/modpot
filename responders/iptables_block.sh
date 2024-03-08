#!/bin/bash

# Usage: ./iptables_block.sh <IP_TO_BLOCK>

IP_TO_BLOCK=$1
DURATION_DAYS=2 # Set the fixed duration of days for the IP block

# Check if IP address is provided
if [ -z "$IP_TO_BLOCK" ]; then
    echo "Error: No IP address provided."
    echo "Usage: ./iptables_block.sh <IP_TO_BLOCK>"
    exit 1
fi

# Add iptables rule to block the IP
sudo iptables -A INPUT -s "$IP_TO_BLOCK" -j DROP
echo "Blocked IP $IP_TO_BLOCK"

# Schedule rule removal after DURATION_DAYS
echo "sudo iptables -D INPUT -s $IP_TO_BLOCK -j DROP" | sudo at now + ${DURATION_DAYS} days
echo "Scheduled removal of IP block $IP_TO_BLOCK after $DURATION_DAYS days"
