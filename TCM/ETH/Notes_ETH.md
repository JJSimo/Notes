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


## AD LAB

![[Pasted image 20240217122304.png]]