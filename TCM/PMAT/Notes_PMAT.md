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
