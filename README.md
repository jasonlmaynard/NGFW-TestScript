# NGFW-TestScript
This script is meant to test Firepower using real world threats. The goal is to populate Firepower with events and tune signatures as required - this can be used as a learning tool. NOTE: these are real threats that may compromise your system or systems. 

The script performs the following: 
Pings an upstream device to ensure the firewall is passing ICMP, Performs 4 NMAP scans (XMAS, FIN, NULL and UDP) on an upstream device
Performs 1 URL check for Adult - playboy.com
Pulls Malware Domain list from Malware Domains, parses it, removes duplicates
Pulls malicious URLS from VXVault
Pulls SPAM and Other Domain, parses it, removes duplicates

Use at YOUR OWN RISK! 
