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

### Native C vs Android Runtime
C and C++ -->  are the device's native language
=>
- does not require VM

Java is easier to code => programmers prefer to write app in Java
- <font color="#00b050">Kotlin</font> becomes the new coding standard 
- Kotlin is utilized by almost 60% of the apps in the play store

### JAVA API Framework
Allows apps to interact with other apps

Content Providers:
way of sharing data to other apps via specific directory
`content://<app-URI>/directory

### System Apps Layer
Pre-installed apps on the Android phone

## App Security and Signing Process
Android Apps can be always:
- reverse-engineered
- rebuilt
- re-signed
- re-run

Apps to do that -->  jadx and apktool

### Compilation Process
![[Pasted image 20250423105921.png|600]]

### App Signing
Since anyone can modify an app and publish it -->  how do we ensure its integrity?
By using -->  Public Key Cryptography

3 ways to verify signatures:
- APK Signature scheme (v1, v2, v3)
- Google Play signing
- keytool, jarsigner, zipalign

Normal Signing Process:
![[Pasted image 20250423110131.png]]

If an app is not signed =>  it won't run on any android device

# Android LAB Setup
## Tools
- JADX-GUI
- Android Studio
- adb
- apktool
- frida
- objection

## Android Studio
### Create a new Virtual Device
- Open Android Studio
- Click on the the `Device Manager` icon > `+` > `Create Virtual Device`
	![[Pasted image 20250228152550.png]]
- Select the Device that you want and the OS version 
  (here you can decide if you want the playstore)

> [!warning]
> Playstore = no root

### Running Device without opening Android Studio
You need to create a Virtual Device from Android Studio before doing that
```shell
Android/Sdk/emulator/./emulator -avd Pixel_9_API35 -writable-system
```

### Access Virtual Device Through Network
<span style="background:#fff88f">From the emulator pc:</span>
```shell
adb -a nodeaemon server
```

If you have an error (cannot bind to 0.0.0.0:5037):
=>
- kill adb process
- re-run the above command

<span style="background:#fff88f">From the remote pc:</span>
```shell
adb -H <local_machine IP> -P 5037 shell
```

## Setup Physical Phone 
1. Enable Developer Mode (usually under settings -> About Phone -> Software Version -> Click Build Number 9 times)
2. Enable USB Debugging
3. Plug in phone and trust the device
4. Enable keep awake when charging (if wanted)

# Android CTF
## Injured Android
A vulnerable Android application with ctf examples based on bug bounty findings, exploitation concepts, and pure creativity.
=>
https://github.com/B3nac/InjuredAndroid

# Android Static Analysis
## Installing apk
### You have the apk
<span style="background:#fff88f">If the client gives you the apk:</span>
=>
- connect the phone to the pc
- then: `adb install /path/to/apk.apk`

### You need to Download the app from the playstore
<span style="background:#fff88f">If the client tells you to download the app from the playstore:</span>
=>
- you don't have problems to download the app from the playstore
- you won't have the apk into your pc 

### Copy app from Phone to PC
```shell
adb shell
su

# Find the application path
pm list packages | grep <app name>
pm path <what adb returned in the previous command>

# Pull the application
adb pull "path returned by pm path/base.apk" "path on your pc"
```

### APKPure or APKMirror
Link:
- [APKPure](https://apkpure.com) 
- [APKMirror](https://www.apkmirror.com/)
  
You can download apks (also in different versions)
<span style="background:#fff88f">Why is it useful?</span>
maybe with older versions you'll find less security features

##### `.xapk` Extension
It's a "new" extension that is something like a zip archive
=>
The .xapk file will include -->  different versions of the apk 
                          (es default version, english version, ARM version)
=>
If you change the extension into `.zip` =>  you'll find all the different `apks` 

The `com.something.app.apk` is the default one

How to install them into the device:
```shell
adb install-multiple "path inside the zip of each apks you want to install"
```

## Android Manifest.xml
Contains the app info:
- minSDKVersion -->  mininum version of android that can run the app
- Permissions -->  what app can access
- Activities -->  UI elements or different screens in the app
- Content Providers -->  utilized to serve data from your app to other apps

### Permissions
Defines what data and HW components the app needs access to:
- Camera
- Contact
- Internet
- Read/Write External Storage
- Package Management
- Bluetooth
- ...

All Manifest Permissions Documentation: [https://developer.android.com/reference/android/Manifest.permission](https://developer.android.com/reference/android/Manifest.permission)

### Activities
UI elements or different screens in the app

Some activities need to be protected:
- Account Details
- Money Transfer Screens
- Hidden Screens

Often performed through -->  <font color="#00b050">intent-filters</font>

An `exported="True"` activity:
can be accessed from outside the app

### Content Providers
Utilized to serve data from your app to other apps
Sometimes used also for:
- shared data between related apps

<font color="#ff0000">If Content Providers are exported:</font>
=>
can be very dangerous -->  since expose data to any user or app on the device

### Read Android Manifest
- Open the apk in jadx
- Go to Resources > `Android Manifest.xml`

Example:
![[Pasted image 20250423114841.png]]
![[Pasted image 20250423115016.png]]
1) Minimum Android Version
2) App Permissions
3) Activities
4) Intent-filters

## Manual Static Analysis
