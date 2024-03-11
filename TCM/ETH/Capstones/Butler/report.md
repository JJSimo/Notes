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

inside the winpeas output we can find something intresting:
![[Pasted image 20240215160050.png]]
<span style="color:#00b050">What it means:</span>
- There is process called WiseBootAssistant
- Run as administrator
- the process runs the .exe inside the path in the image
- the path has:
	- <span style="color:#00b050">no quotes</span> -->  so is not inside " "
	- <span style="color:#00b050">space detected</span> -->  as you can see inside some of the subdir there are some 
	                    spaces
<span style="color:#00b050">Why is this useful:</span>
every time windows tries to execute this process:
- Every time windows finds a space in the path => it tries 1 of all to add .exe
     Es con Wise Care 365 -->  quando arriva a Wise 
                          =>
                          prima prova con Wise.exe
                          fa così per tutto il path -->  finchè non esegue il .exe
> [!INFO] 
> How to fix this problem:
> put the path inside " "

<span style="color:#00b050">What we can do:</span>
- We can create a reverse_shell and call it Wise
- Put it inside the Wise Folder
- => 
     in this way windows:
     - before will enter inside the Wise Care 365
     - will execute our shell

### Create Reverse Shell
Follow these [[cheet#Create and rename a shell|steps]]
then:
- create a web server from the attacker to upload the reverse shell
- dowload the reverse shell from the victim with `certutil`
![[Pasted image 20240215162609.png]]
then:
`move Wise.exe "C:\Program Files (x86)\Wise\"`

Now we can't just execute the .exe:
bc -->  in this way it will execute as normal user
=>
<span style="color:#00b050">we need to stop and restart the Service the we found with winpeas:</span>
`sc stop WiseBootAssistant`      stop the service
`sc query WiseBootAssistant`    check if the service is down
`sc start WiseBootAssistant`    run the service

inside our netcat listener:
![[Pasted image 20240215163850.png]]

<span style="color:#00b050">We have a root shell</span>

