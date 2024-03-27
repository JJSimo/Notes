# Connecting to HTB VPN
 VMs/networks:
 require players -->  to connect to the target network via a VPN         (to access the private lab net)
 =>
 - download the `user.ovpn` from HTB
 - `sudo openvpn user.ovpn`
	 - when you read:![[Pasted image 20240327123731.png]]
	   =>
	   we successfully connected to the VPN

- by typing `ifconfig` we can see the new interface `tun0`