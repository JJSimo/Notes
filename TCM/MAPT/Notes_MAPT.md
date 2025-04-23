# Resources
<span style="background:#fff88f">Mobile Pentesting OWASP Gitbook:</span>
[https://mas.owasp.org/MASTG/](https://mas.owasp.org/MASTG)

<span style="background:#fff88f">OWASP Mobile Top 10: </span>
[https://owasp.org/www-project-mobile-top-10/](https://owasp.org/www-project-mobile-top-10/)

<span style="background:#fff88f">HackTricks Checklist (Android): </span>
[https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html#android-applications-pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html#android-applications-pentesting)

<span style="background:#fff88f">HackTricks Checklist (iOS): </span>
[https://book.hacktricks.wiki/en/mobile-pentesting/ios-pentesting/index.html?highlight=iOS#ios-pentesting](https://book.hacktricks.wiki/en/mobile-pentesting/ios-pentesting/index.html?highlight=iOS#ios-pentesting)

My resources:
- MASTG
  https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0052/
- iOS STATIC ANALYSIS
  https://infosecwriteups.com/ios-penetration-testing-guide-to-static-analysis-4a9dea5d672d
- IVAN GUIDE
  https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet

# Mobile Application Penetration Process
## Reconnaissance
- Search app in playstore/appstore to read/understand what the app does
- Enumerate the different app versions and patch notes

## Static Analysis
- Read app code and search for:
	- Hardcoded strings and credentials
	- Security misconfigurations

## Dynamic Analysis
- Intercept traffic
- Dumping memory from app to check for insecurely stored data
- Checking local storage for files created at runtime
- Breaking SSL pinning and root detection

# Android Architecture
Android is based on the Linux OS

## ART
Every app is run in:
virtual machine -->  known as Android Runtime (ART)

ART:
- moderns translation layer from app's bytecode to device instructions
- every app runs in its own sandboxed virtual machine
- in the FS apps are isolated by creating a new user unique for that app

## Access Management
=>
Each app:
- has its own user for the app
- this user is the owner of the app directory (UID between 10000 and 999999)
![[Pasted image 20250423103724.png]]
=>
This stops apps from:
interacting with each other -->  unless explicitly granted permissions 

Having Root device -->  allows to access all the apps

## Mayor Layer Android Architecture
- Linux Kernel
- Hardware Abstraction Layer
- Libraries (Native C or Android Runtime)
- Java API Layer
- System Apps
![[Pasted image 20250423104359.png|450]]

### Hardware Abstraction Layer (HAL)
Allows apps to -->  access HW components irrespective of the device manufacturer or type
=>
Allows apps to simply access -->  camera, microphone, GPS, ...







