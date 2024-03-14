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
- Open [[cheet#VIRUSTOTAL]]
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

How to do that -->  with [[cheet#FLOSS]]

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

we are going to use -->  [[cheet|PEview]]
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
- open the packet malware with [[cheet#PEview]]
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
2) these hashes have a direct link to [[cheet#VIRUSTOTAL|VIRUSTOTAL]]   (right click on the hash > copy link)
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

add this to the note [[1.2-RAT.Unknown.exe]]

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
save this inside the [[1.2-RAT.Unknown.exe|report]] as -->  host indicator

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
=>
update note