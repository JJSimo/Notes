Introduction to:
- Malware analysis 
- reverse engineering
- triage

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
      
- When the installation is done =>  TAKE ANOTHER SNAPSHOT -->  call it flareVM-clean
