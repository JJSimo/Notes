ftp port 21:
version vsftpd 3.0.3
allows anonymous login

ssh port 22
version OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

http port 80
version  Apache httpd 2.4.38 ((Debian))


80 - 192.168.5.5 - 16:50 14/02/2024
Default Webpage - Apache - PHP



![[Pasted image 20240214104859.png]]

- `sudo netdiscover -r 10.0.2.0/24`
- `nmap -T4 -p- -A 10.0.2.152`  
- port 80 open => try to look at http://10.0.2.152
- `nikto -h http://10.0.2.152`
- 
