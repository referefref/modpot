#!/bin/bash

# Replace placeholders in the template with actual values
template=$(cat email.template)
template=${template//%ID%/$1}
template=${template//%APPLICATION%/$2}
template=${template//%DATETIME%/$3}
template=${template//%IPSOURCE%/$4}
template=${template//%LOGEVENT%/$5}

# Email subject
subject="Modpot Alert: $2"

# Recipient email
to="alerts@domain.com"

# Sender email
from="modpot@domain.com"

# Temporary file for the email content
tempfile=$(mktemp)

# Prepare email content
echo "To: $to" > $tempfile
echo "From: $from" >> $tempfile
echo "Subject: $subject" >> $tempfile
echo "Content-Type: text/html" >> $tempfile
echo "" >> $tempfile
echo "$template" >> $tempfile

# Send the email using msmtp
msmtp -a default $to < $tempfile

# Clean up
cat $tempfile
rm $tempfile
