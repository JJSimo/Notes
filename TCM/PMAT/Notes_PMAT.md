Introduction to:
- Malware analysis 
- reverse engineering
- triage

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
  