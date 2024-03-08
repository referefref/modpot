[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dwyl/esta/issues)

# modpot v0.3.11 (Not for workgroups)
![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white)![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

![modpot-wide](https://github.com/referefref/modpot/assets/56499429/409d59b0-9e14-45f7-abdc-abe721e0e678)
![image](https://github.com/referefref/modpot/assets/56499429/f13d4e39-becd-48da-aee1-29e21b921ce4)

modpot is a modular web application honeypot framework written in Golang and making use of gin framework.
It is the antithesis to [***honeydet***](https://github.com/referefref/honeydet) in many ways and allows the user to deploy simple html/js honeypots that mimic web applications in order to detect requests and form entries that are related to attacks. Responders offer a modular capacity for automation and logging pipelines and are not limited by programming language.
modpot is best utilised alongside [***honeypage***](https://github.com/referefref/honeypage) a tool that creates flattened single html file versions of web applications, which makes them portable and easy to use with modpot.

## Responders
![image](https://github.com/referefref/modpot/assets/56499429/c0f09791-3ebc-4159-b47e-a1669485f29d)

Responders allow for simple triggering of automation, logging, or connection to SOC platforms. 
The parameters that can be passed to responders are ID, Application, Datetime, IP Source, Log Event.

Included are the following examples:
* Email
* iptables - time window blocking
* SMS (Using twilio)
* Slack - webhook
* Syslog
* Splunk - HEC endpoint
* Webhook-generic

## Example config
```yaml
honeypots:
  - id: 1
    name: "ExampleHoneypot1"
    cve: "CVE-2021-XXXX"
    application: "FakeWebApp1"
    port: 8081
    enabled: true
    template_html_file: "index1.html"
    detection_endpoint: "/fakeapp"
    request_regex: ".*attack.*"
    redirect_url: "https://jamesbrine.com.au/"
    date_created: "2022-01-01"
    date_updated: "2022-01-02"
    responders:
      - engine: "/usr/bin/bash"
        script: "email.sh"
        parameters: ["honeypots.id", "honeypots.application", "honeypot_logs.datetime", "honeypot_logs.ip_source", "honeypot_logs.log_event"]
      - engine: python3
        script: sms.py
        parameters: ["honeypots.id", "honeypots.application", "honeypot_logs.datetime", "honeypot_logs.ip_source", "honeypot_logs.log_event"]
      - engine: "/usr/bin/bash"
        script: "iptables_block.sh"
        parameters: ["honeypot_logs.ip_source"]

  - id: 2
    name: "ExampleHoneypot2"
    cve: "CVE-2022-YYYY"
    application: "FakeWebApp2"
    port: 8082
    enabled: true
    template_html_file: "index2.html"
    detection_endpoint: "/anotherapp"
    request_regex: "^/admin"
    redirect_url: "test.html"
    date_created: "2022-02-01"
    date_updated: "2022-02-02"
```

## Note
I am not responsible for your use/mis-use of this application. It was created for research purposes and is not intended nor do I or it's existence give implicit authority to use it as a phishing tool or for any other malicious purposes. Now, with the boring stuff out of the way.

## Todo
* Tidy up web frontend and features (search, filter, paginate etc.)
* Allow for multi-step configs for more complex honeypages
* Set up reporting/alerting on match and allow configuration through web frontend
* Build honeypage into modpot, allowing the page download process to take place through the "Add honeypot" button in the main interface
