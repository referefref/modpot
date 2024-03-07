import sys
from twilio.rest import Client

# Twilio settings - replace these with your Twilio account details
ACCOUNT_SID = 'YOUR_ACCOUNT_SID'
AUTH_TOKEN = 'YOUR_AUTH_TOKEN'
TWILIO_PHONE_NUMBER = 'YOUR_TWILIO_PHONE_NUMBER'
DESTINATION_PHONE_NUMBER = 'DESTINATION_PHONE_NUMBER'

def send_sms(honeypot_id, application, datetime, ip_source, log_event):
    # Initialize Twilio client
    client = Client(ACCOUNT_SID, AUTH_TOKEN)

    # Format the message
    message_body = f"*Alert from Modpot:*\n- Honeypot ID: {honeypot_id}\n- Application: {application}\n- Datetime: {datetime}\n- IP Source: {ip_source}\n- Log Event: {log_event}"

    # Send the message
    message = client.messages.create(
        body=message_body,
        from_=TWILIO_PHONE_NUMBER,
        to=DESTINATION_PHONE_NUMBER
    )
    print(f"Message sent: {message.sid}")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: sms.py <honeypot_id> <application> <datetime> <ip_source> <log_event>")
        sys.exit(1)

    _, honeypot_id, application, datetime, ip_source, log_event = sys.argv
    send_sms(honeypot_id, application, datetime, ip_source, log_event)
