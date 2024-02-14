ftp port 21:
version vsftpd 3.0.3
allows anonymous login

ssh port 22
version OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

http port 80
version  Apache httpd 2.4.38 ((Debian))


80 - 192.168.5.5 - 16:50 14/02/2024
Default Webpage - Apache - PHP



![[Pasted image 20240214104859.png]]

- `sudo netdiscover -r 10.0.2.0/24`
- `nmap -T4 -p- -A 10.0.2.152`  
- port 80 open => try to look at http://10.0.2.152
- `nikto -h http://10.0.2.152`
- 
#### FTP
- port 21 open
- There is a file         [[Notes/TCM/Capstones/Academy/nmap|Look inside nmap scan]]
=>
try to connect as anonymous 
`ftp 10.0.2.152`
`anonymous`
try to get the file -->  `get note.txt`

> [!TIP] This can be intresting:
>- we don't know the file position inside the victim machine
>- HTTP is open =>  always good to check if` http://10.0.2.152/note` exists
>- if exist => we can <span style="color:#00b050">upload</span> a malicious <span style="color:#00b050">file using FTP</span>
>- execute it
	
exit from ftp and `cat note.txt`
![[Pasted image 20240214154532.png]]
- We found a password
- Probably is an hash
- Check what type with tool [[cheet#Hash-identifier|hash-identifier]] 
- `hash-identifier
- `cd73502828457d15655bbd7a63fb0bc8`
- probably is a --> MD5 hash
	- => try to crack hash with [[cheet#hashcat|hashcat]] + [[cheet#Locate|locate]]
	- locate rockyou.txt
	- echo "type here the hash" > hash.txt
	- `hashcat -m 0 Desktop/TCM/ETH/VMe/Academy/hash.txt` `Desktop/TCM/rockyou.txt` 
	- <span style="color:#00b050">We found a password</span> -->  student
	- ![[Pasted image 20240214160424.png]]

Now we have a userid + password 
But we don't know for what it's used
=>
Let's check if it exists a web page where we can enter these credentials
=>
#### Enumerate HTTP
we can use [[cheet#dirb|dirb]] or [[cheet#ffuf|ffuf]]
`ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ_VARIABLE -u http://10.0.2.152/FUZZ_VARIABLE`
=>
<span style="color:#00b050">we found an "academy" path</span>
![[Pasted image 20240214162425.png]]
- go to `http://10.0.2.152/academy `and try to login with the userid + pass
- <span style="color:#00b050">We can login </span>



