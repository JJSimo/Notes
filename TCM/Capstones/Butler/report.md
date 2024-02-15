8080 - 10.0.2.80 -  15/02/2024
Web login page jenkins


### Bruteforcing Login
#### BurpSuite
Follow all these [[cheet#Bruteforcing Login|steps]]
##### Images
![[Pasted image 20240215142638.png]]
![[Pasted image 20240215142644.png]]
![[Pasted image 20240215142653.png]]


If we launch the attack:
![[Pasted image 20240215145510.png]]
In our example:
the sixth one is different in length from all the other try
Indeed if we go to the response we can see that -->  here it has been set a Cookie
                                          (in all the other try not)
=>
(first disable interception in BurpSuite and disable the proxy in the plugin)
let's try to login with -->  username: jenkins password: jenkins
<span style="color:#00b050">Credentials work</span>

### Get a shell
We need to find a way to -->  <span style="color:#00b050">execute some codes inside the website</span>
Inside the website there are a lot of sections
Inside "Manage Jenkins" there is a -->  Script Console
                                "Type in an arbitrary [Groovy script](http://www.groovy-lang.org) and execute it on the server."
![[Pasted image 20240215152803.png]]
=>
we can search for -->  [jenkins groovy reverse shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
=>
- Paste the reverse shell in the form
- Change the host to the attacker ip
- Use nc to listen on 8044
- Run the script inside the form from the website
![[Pasted image 20240215153027.png]]

=>
<span style="color:#00b050">We got a shell </span>   (unprivileged)
![[Pasted image 20240215153423.png]]

#### Privilege Escalation
We obtain a shell without root permissions
=>
We need to get root access

first step: 
systeminfo  -->  to get info about the machine (example <span style="color:#00b050">architect x86, x64</span>)

We'll use [[cheet#winpeas|winpeas]] -->  same as [[cheet#linpeas|linpeas]], but for windows
Follow the steps
