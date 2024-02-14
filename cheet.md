#### Virtual Box
Set VM internet:
- **Bridge** -->  conn a internet   (selezioni il ponte in base a se sei conn al wifi o ethern)
- Nat -->  conn a internet + conn tra diverse vm

Per Nat:
devi creare una NatNetwork =>       - File > Tools > Network Manager
						     - seleziona Nat Networks
						     - Create

----
## Tools
#### Netdiscover
tools for scanning the entire net to find hosts ip (using arp)
`sudo netdiscover -r 10.0.2.0/24`           -r = scan a given range instead of     
                                    auto scan

----
#### Nmap
tools for scanning ports to identify open ports
`nmap -T4 -p- -A 10.0.2.152`
`nmap -Pn --script smb-vuln* -p 139,445 10.0.2.152`

`-T4` —> set scan velocity from 1 to 5 (1 slow but complete - 5 fast but)
`-p-` —> scan all ports (without scann only 1000 most known) 
`-A` —> show me all that you found
`-Pn` --> treat all hosts as online -- skip host discovery

-----

### Enumerating HTTP e HTTPS
#### Nikto
scanning website vulnerabilities
`nikto -h http://10.0.2.152`      -h = host


