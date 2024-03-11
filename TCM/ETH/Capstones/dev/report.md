80 - 10.0.2.155 -  14/02/2024
Error Webpage - Bolt - PHP


8080 open:
Info about PHP - PHP Version 7.3.27

2049/tcp  open:
nfs

### 80 and 8080
enumerating <span style="color:#ff0000">both</span> with -->  [[cheet#Dirbuster]] + [[cheet#ffuf]] + [[cheet#dirb]]
we'll find a lot of directories

### nfs
Network File System is open
=>
let's see if there is a mount point for the nfs
=>
`showmount -e 10.0.2.155`     (victim ip)
![[Pasted image 20240215112745.png]] 
there is something in -->  /srv/nfs
=>
- create a temp directory
- mount inside it the nfs
=>
`sudo mkdir /mnt/dev`
`sudo mount -t nfs 10.0.2.155:/srv/nfs /mnt/dev/`
inside there is a zip
![[Pasted image 20240215112949.png]]
<span style="color:#00b050">Ask for a password to unzip</span> 

=>  we can try to bruteforce it

#### fcrackzip
we are going to crack the zip with [[cheet#fcrackzip|fcrackzip]]
inside /mnt/dev:
`fcrackzip -v -u -D -p Desktop/TCM/rockyou.txt save.zip`
![[Pasted image 20240215115128.png]]
=>
- <span style="color:#00b050">we have found the password</span>
- we can unzip the zip
	- there are 2 files:
		- <span style="color:#00b050"> id_rsa</span> -->  a SSH key
		- <span style="color:#00b050">todo.txt </span>-->  at the end there is a signature ("jp")
- =>
      we can try to connect via ssh using the key and the signature as user
- `ssh -i id_rsa jp@10.0.2.155`
- ![[Pasted image 20240215115422.png]]
- <span style="color:#00b050">we don't have the password</span>

let's try to find something intresting inside the subdomains in 80 and 8080

### 80 and 8080
enumerating <span style="color:#ff0000">both</span> with -->  [[cheet#Dirbuster]] + [[cheet#ffuf]] + [[cheet#dirb]]
we'll find a lot of directories

There is an interesting subdomain at -->  http://10.0.2.155:8080/dev
![[Pasted image 20240215115716.png]]


#### Exploit BoltWire
we can search for -->  [BoltWire exploit](https://www.exploit-db.com/exploits/48411)  (and we can this one)
=>
- we need to authenticate inside the website above
- paste the url
![[Pasted image 20240215115954.png]]

- result:
- ![[Pasted image 20240215123501.png]]
- We have found -->  a real user
- =>
	   let's retry the ssh login with this user
	- ask for a password
	- inside 1 other file we found a password -->  I_love_java
	- let's try --> <span style="color:#00b050"> it works</span>
	- ![[Pasted image 20240215123917.png]]
### Privilege Escalation
Now we are inside as a normal user
we need to get root acces
=>
first command -->  `sudo -l` 
                 tells you which command you can execute as root without inserting the root password
=> <span style="color:#00b050">we can use zip as root</span>

#### GTFOBins
Let's search for [[cheet#GTFOBins]]
we are looking for having root access using zip command
=>
search for zip
![[Pasted image 20240215124755.png]]
=>
type inside the ssh connection:
`TF=$(mktemp -u)`
`sudo zip $TF /etc/hosts -T -TT 'sh #'`
![[Pasted image 20240215125237.png]]
<span style="color:#00b050">we have root access </span> 