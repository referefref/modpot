# modpot
modpot is a modular web application honeypot framework written in Golang and making use of gin framework.
It is the antithesis to [***honeydet***](https://github.com/referefref/honeydet) in many ways and allows the user to deploy simple html/js honeypots that mimic web applications in order to detect requests and form entries that are related to attacks. It has the accidental capability to act as a phishing server, capturing credentials though this is not its main intention.
modpot is best utilised alongside [***honeypage***](https://github.com/referefref/honeypage) a tool that creates flattened single html file versions of web applications, which makes them portable and easy to use with modpot.

![modpot-wide](https://github.com/referefref/modpot/assets/56499429/409d59b0-9e14-45f7-abdc-abe721e0e678)
![image](https://github.com/referefref/modpot/assets/56499429/f13d4e39-becd-48da-aee1-29e21b921ce4)

## Note
I am not responsible for your use/mis-use of this application. It was created for research purposes and is not intended nor do I or it's existence give implicit authority to use it as a phishing tool or for any other malicious purposes. Now, with the boring stuff out of the way.

## Todo
* Tidy up web frontend and features (search, filter, paginate etc.)
* Allow for multi-step configs for more complex honeypages
* Set up reporting/alerting on match and allow configuration through web frontend
* Build honeypage into modpot, allowing the page download process to take place through the "Add honeypot" button in the main interface

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

  - id: 3
    name: "SMRS Portal"
    cve: ""
    application: "SMRS Portal"
    port: 8003
    template_html_file: "smrs.html"
    detection_endpoint: "Login"
    request_regex: "^.*1=1.*$"
    date_created: "2024-02-17"
    date_updated: "2024-02-17"
    redirect_url: "https://jamesbrine.com.au"
    enabled: true
```
