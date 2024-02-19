# modpot
Modular web-application honeypot platform built using go and gin

![modpot-wide](https://github.com/referefref/modpot/assets/56499429/409d59b0-9e14-45f7-abdc-abe721e0e678)
![image](https://github.com/referefref/modpot/assets/56499429/f13d4e39-becd-48da-aee1-29e21b921ce4)


# Example config
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
