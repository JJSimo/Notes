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


<span style="background:#fff88f">To use all the android studio integrated tools:</span> (example `zipalign`, `jarsigner`, `aapt` )
- add in your `.zshrc`:
  `export PATH=$HOME/Android/Sdk/build-tools/35.0.0:$PATH`

## Upgrade
- pip3 install --upgrade objection
- pip3 install --upgrade frida
- pip3 install --upgrade frida-tools
- apktool --version (always make sure you are on the latest version as shown here: [https://ibotpeaches.github.io/Apktool/](https://ibotpeaches.github.io/Apktool))

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

An `exported="true"` activity:
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

Check if you find:
activities or Content Providers -->  with `exported=true`
=>
- in the Manifest to ctrl+f and search for it
- check if these activities/content providers contain sensitive info

## Manual Static Analysis
```shell
apktool d app.apk
```

## Find Hardcoded Strings
Examples:
- Credentials
- URL Exposed
- API Key 
- Firebase URLs

=>
- Open jadx
- Go to Resources > resources.arsc > values
- Open `strings.xml` to see -->  hardcoded strings

Check also the `xmls.xml` file in the same 

Use ctrl+f to search for:
- password/pin
- user
- API
- firebase.io
  if you find a firebase.io URL:
	- copy the link and add to it `/.json`
	- paste it in a browser
	- if the response is `permission denied` => it's secure
- SQL
- key

Then:
do the same thing with the global search in jadx

## Enumerating AWS Storage Bucket
[https://github.com/initstring/cloud_enum](https://github.com/initstring/cloud_enum)

## Enumerating Firebase Databases
[https://github.com/Sambal0x/firebaseEnum](https://github.com/Sambal0x/firebaseEnum)

```shell
git clone https://github.com/Sambal0x/firebaseEnum
cd firebaseEnum
mkvirtualenv/workon firebase-enum
pip3 install -r requirements.txt
```

## Automate Analysis
### MobSF
[https://github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

# Android Dynamic Analysis
## SSL Pinning
Methodology utilized to -->  ensure that app traffic is not being intercepted

Some apps:
- verify that the received traffic is <font color="#00b050">coming from a known cert</font>
  =>
  we can import a certificate
  (but it still might not be trusted by the app)

<span style="background:#fff88f">Traffic Intercept Process:</span>
- Start proxy SW (Burp Suite)
- Configure proxy SW
- Set proxy on the phone/emulator
- Intercept HTTP traffic (to check if the proxy works)
- Import CA burp certificate into the phone
- Trust the CA cert in the phone
- Try to intercept HTTPS traffic
	- If you can't:
		- App does SSL Pinning
		- Try to bypass it by using Frida or Objection

## MOBSF
To perform dynamic analysis with MOBSF:
- you need an emulator without Google Play Store

Follow this guide:
https://mobsf.github.io/docs/#/dynamic_analyzer_docker?id=android-studio-emulator

It allows to:
- Bypass SSL Pinning
- Monitor APIs
- "Capture" https traffic (more or less)
- Instrument the app through frida
- Use Logcat

## Burp
In burp setup a Proxy listener on all the interfaces
### Download and Edit the Burp Certificate
#### Download the Burp certificate
- Open burp and go to Settings > Proxy > Import / export CA certificate
- Select under Export `Certificate in DER format` and save it as `cacert.der`

#### Convert der in pem format
Now we need to convert the certificate to `pem` format:
```shell
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
mv cacert.pem <value_returned>.0
```

### Setup BurpSuite Proxy
Same steps described here (more or less) -->  [Configuring Burp Suite with Android and iOS](https://wikolo.securenetwork.it/en/tech/mobile/Configuring_BurpSuite_with_Android_iOS)
=>

Run the emulator:
```shell
 Android/Sdk/emulator/./emulator -avd Pixel_6_Pro_API_34 -writable-system
```
where `Pixel_6_Pro_API_34` is the Android emulator name

Now:
follow the correct steps (based on your Android Version)

>[!danger]
> For opensuse, <font color="#ff0000">DISABLE FIREWALLD</font>
> `sudo systemctl stop firewall`

#### Before Android 10
```shell
adb root
adb remount
adb push <cert>.0 /sdcard/
adb shell

# for devices with android prior to 10; otherwise, "read only file system" error is returned
mv /sdcard/<cert>.0 /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/<cert>.0
chmod 644 /system/etc/security/cacerts/<cert>.0
reboot
```

```shell
adb shell
settings put global http_proxy 10.220.106.87:8080
```

>[!danger]
> Setup Burp Proxy with the same IP specified in the previous command
> <font color="#ff0000">Can't be localhost:</font>
> Set it to one of your local interface

Set BurpSuite proxy with the same IP (in the examle 10.220.106.87)

#### Android 10+
##### First time
Save this script locally:
```shell
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp /sdcard/certificates/* /system/etc/security/cacerts/

chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
```

Then:
```shell
adb root
adb push <cert>.0 /sdcard/
adb push /home/simone/Desktop/PT/Unicredit/mobile/add_cacert_android10avd.sh /sdcard/add_cacert_android10avd.sh
adb shell

# we need to prepare the directory for the tmpfs
mkdir /sdcard/certificates
cp /system/etc/security/cacerts/* /sdcard/certificates/
cp /sdcard/*.0 /sdcard/certificates/
```

Run the lines in the `add_cacert_android10avd.sh` script:
```shell
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp /sdcard/certificates/* /system/etc/security/cacerts/

chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
```

After each reboot:
```shell
adb root && adb shell sh /sdcard/add_cacert_android10avd.sh && adb shell settings put global http_proxy 10.220.106.104:8082 && echo Done!
```

>[!danger]
> Setup Burp Proxy with the same IP specified in the previous command
> <font color="#ff0000">Can't be localhost:</font>
> Set it to one of your local interface

#### Android 14
[Configuring Burp Suite with Android and iOS](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/)

Save locally this script as `injectCA.sh`:
change `$CERTIFICATE_PATH` with `/data/local/tmp/$CERT_HASH.0`

```bash
# Create a separate temp directory, to hold the current certificates
# Otherwise, when we add the mount we cannott read the current certs anymore.
mkdir -p -m 700 /data/local/tmp/tmp-ca-copy

# Copy out the existing certificates
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Copy the existing certs back into the tmpfs, so we keep trusting them
mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

# Copy our new cert in, so we trust that too
mv $CERTIFICATE_PATH /system/etc/security/cacerts/

# Update the perms & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Deal with the APEX overrides, which need injecting into each namespace:

# First we get the Zygote process(es), which launch each app
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
# N.b. some devices appear to have both!

# Apps inherit the Zygote's mounts at startup, so we inject here to ensure
# all newly started apps will see these certs straight away:
for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
    if [ -n "$Z_PID" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- \
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    fi
done

# Then we inject the mount into all already running apps, so they
# too see these CA certs immediately:

# Get the PID of every process whose parent is one of the Zygotes:
APP_PIDS=$(
    echo "$ZYGOTE_PID $ZYGOTE64_PID" | \
    xargs -n1 ps -o 'PID' -P | \
    grep -v PID
)

# Inject into the mount namespace of each of those apps:
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- \
        /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait # Launched in parallel - wait for completion here

echo "System certificate injected"
```

Now:
```bash
adb push $YOUR_CERT_FILE /data/local/tmp/$CERT_HASH.0
adb push injectCA.sh /sdcard/

adb root
adb shell
cd /sdcard/
sh injectCA.sh

settings put global http_proxy <yourIP>:8080
```

>[!danger]
> Setup Burp Proxy with the same IP specified in the previous command
> <font color="#ff0000">Can't be localhost:</font>
> Set it to one of your local interface

After each reboot:
```shell
adb root && adb push 9a5ba575.0 /data/local/tmp/ && adb shell sh /sdcard/injectCA.sh && echo Done!
```

### Disable Proxy
```shell
adb shell
settings put global http_proxy :0000
```

## Proxyman
Intercept traffic on Mac easily 
https://proxyman.com/

Documentation -->  https://docs.proxyman.com/

## Patch app using Objection automatically 
https://github.com/sensepost/objection/wiki/Patching-Android-Applications

Installing objection:
```shell
pip3 install frida-tools
pip3 install objection
```

<span style="background:#fff88f">Patch apk:</span>
```shell
objection patchapk --source app.apk
```
This will:
- Unpack the app
- Inject Frida gadget
- Rebuild the apk

<span style="background:#fff88f">If you got errors try:</span>
To use all the android studio integrated tools:
- add in your `.zshrc`:
  `export PATH=$HOME/Android/Sdk/build-tools/35.0.0:$PATH`

try also:
to use -->  `--use-aapt2`

## Patch manually
Follow this article -->  https://koz.io/using-frida-on-android-without-root/
### Decompile the app
- Decompile the apk
```shell
apktool d -r app.apk
```
- It will create a folder with the unpack apk
- We will inject in `lib/arch` the frida-gadget library
- The `arch` depends on your emulator/phone
- In this case is an emulator with `x86-64`
  ![[Pasted image 20250428105622.png]]

### Inject Frida Gadget
- Download from here the frida-gadget with the correct arch and version 
  (same version as frida installed on phone and pc)
  (https://github.com/frida/frida/releases?page=2)
	- In this case `frida-gadget-16.7.0-android-x86_64.so`
	  
- `unxz frida-gadget-16.7.0-android-x86_64.so`
- Change its name in `libfrida-gadget.so`
- Copy it in `lib/x86_64/`

### Update `smali` code
- Open the smali folder
- Find the smali related to the app 
  (try to search the app name in the folder to see if you can find it)
- In this case the folder is -->  `hu/cardinal/vica/`
- Open an activity that you know will used -->  for example `MainActivity.smali`
- Insert after the red rectangular the code![[Pasted image 20250428111342.png]]
```smali
const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

### Internet Permission
- Check in the [[Notes_MAPT#Read Android Manifest]] if there is the INTERNET permission

If not add it:
```
<uses-permission android:name="android.permission.INTERNET" />
```

### Rebuild the app
```
apktool b app_decrypted_folder -o app-patched.apk
```

### Sign the app
```shell
# Create a keystore to sign the app with
keytool -genkey -v \
  -keystore sn.keystore \
  -alias snkeystore \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -sigalg SHA256withRSA0
# Password -->  testsn1

# Fill the field and type yes

# sign the APK
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore sn.keystore -storepass testsn1 app-patched.apk snkeystore

# verify the signature you just created
jarsigner -verify app-patched.apk

# zipalign the APK
/home/simone/Android/Sdk/build-tools/35.0.0/zipalign 4 ViCA-patched.apk ViCA-final-patched.apk
```

Now you can install it 

## Frida CodeShare
https://codeshare.frida.re/

Ready to use script to use with frida

## Database
```shell
adb shell
cd /data/data/
ls | grep appname
cd apppackage name

# Search for database files or a folder
# Outside adb:
adb pull /data/data/apppackage/database/dbnamr.db

# Install sqlite
sudo zypper install sqlitebrowser

# Open the db with sqlite
```

# Android Recap
- Check the Manifest using jadx [[Notes_MAPT#Read Android Manifest]]
	- check the app permissions and all the `exported=true`
- Check the strings and hardcoded things [[Notes_MAPT#Find Hardcoded Strings]]
- Run MobSF [[Notes_MAPT#MobSF]]
- Setup Burp and Proxy [[Notes_MAPT#Burp]]
- Intercept traffic
- Patch the app if SSL Pinning:
	- Automatically -->  [[Notes_MAPT#Patch apps automatically using Objection]]
	- Manually -->  [[Notes_MAPT#Patch manually]]
- Search for database [[Notes_MAPT#Database]]


# iOS Architecture
## Core Security Features
iOS security is structured around six major pillars:
1. **Hardware Security**  
    Each device integrates unique cryptographic keys (UIDs and GIDs) fused into hardware, inaccessible via software or debugging. A dedicated AES engine uses these keys to handle encryption and decryption tasks securely. Devices also support **Effaceable Storage** to securely erase sensitive data.
    
2. **Secure Boot**  
    At startup, the device executes a secure boot chain beginning with Boot ROM, verifying each subsequent software component's signature (LLB, iBoot, kernel). Any failure leads to recovery or DFU modes, ensuring only Apple-signed code runs at boot.
    
3. **Code Signing**  
    All executable code must be signed by Apple. Developers must enroll in the Apple Developer Program to sign and distribute apps.  
    A code signature includes a seal (hashes of code), a digital signature (encrypted seal), and code requirements (verification rules).
    
4. **Encryption and Data Protection**  
    iOS devices implement encryption at hardware and software levels.  
    Apps downloaded from the App Store use **FairPlay** DRM encryption, tied to the user’s Apple ID and device.  
    Data protection uses multiple keys (UID, passcode, file system keys) to secure user data, classifying files into protection classes that determine accessibility based on device state (e.g., locked or unlocked).
    
5. **Sandbox**  
    Apps are confined to isolated containers, limiting access to their own data and approved system resources.  
    System calls are modified to prevent execution of self-modified code, enhancing control over code execution.  
    Direct hardware access is prohibited; interaction must happen through public APIs and frameworks.
    
6. **General Exploit Mitigations**  
    iOS incorporates **Address Space Layout Randomization (ASLR)** to randomize memory locations at runtime and uses the **eXecute Never (XN)** bit to prevent execution of injected code in memory regions like stack and heap.

## iOS Software Development Overview
Apple offers a **Software Development Kit (SDK)** for iOS, enabling developers to create, test, and distribute iOS apps. Development is primarily done using **Xcode**, the official Integrated Development Environment (IDE), and apps are built with **Objective-C** or **Swift**. Swift, introduced in 2014, is the modern successor to Objective-C, offering better interoperability with existing code.

**App Installation Outside the App Store**  
On non-jailbroken devices, apps can be installed via **Enterprise Mobile Device Management** (MDM) with an Apple-signed company certificate, or **sideloading** through Xcode with a developer’s certificate, though the number of devices is limited.

### iOS App Distribution and Structure
iOS apps are distributed in **IPA** files (iOS App Store Package), which are **ZIP-compressed** archives containing all the app's code and resources. These IPA files include:

1. **/Payload/** - Contains all app data, including the executable and resources.
2. **/Payload/Application.app/** - Holds the compiled code and static resources.
3. **/iTunesArtwork** - 512x512 pixel image used as the app's icon.
4. **/iTunesMetadata.plist** - Contains developer information, bundle identifier, and app-related data.
5. **/WatchKitSupport/WK/** - Example of an extension for Apple Watch integration.
    
#### IPA Structure
The **top-level bundle directory** includes the **executable file**, icons, configuration files, **launch images**, **interface files (e.g., MainWindow.nib)**, **Settings.bundle** (for app settings), and resources (images, sound files, etc.). It also contains language-specific subdirectories (e.g., **en.lproj**) with **storyboards** and **strings files**.

On jailbroken devices, developers may decrypt and install IPA files using various tools.

### App Permissions in iOS
Unlike Android, iOS apps request permissions **at runtime** when accessing sensitive data or hardware (e.g., contacts, camera, location). Users can **grant or deny** permissions, and the app can only proceed after explicit approval. Permissions are listed in **Settings > Privacy**. Since iOS 10, apps must provide **usage descriptions** for requested permissions (e.g., NSContactsUsageDescription).

Common permissions include access to **Contacts**, **Microphone**, **Camera**, **Location**, and more.

### DeviceCheck and App Attest Frameworks
- **DeviceCheck** helps prevent fraud by storing information about a device on both the device and Apple’s servers. It is useful for limiting resources per device (e.g., one promotion per device) but cannot prevent all forms of fraud.
    
- **App Attest**, a part of **DeviceCheck**, ensures the app's legitimacy by verifying that it is running on a genuine Apple device. It uses **cryptographic keys** to authenticate requests and verify app integrity, helping prevent modified or fraudulent apps from interacting with servers. However, it does not guarantee complete protection from all fraud types.
    
