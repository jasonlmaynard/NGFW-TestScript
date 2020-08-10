__author__ = 'Jason Maynard'
#
import os
import os.path
import urllib.request
import socket

#
print ('################################################################')
print ('Author: Jason Maynard')
print ('Twitter: FE80CC1E')
print ('Version = 3.3')
print ('################################################################')
print ('Using this script may compromise your assets.')
print ('Use this script at your own risk')
print ('I accept no responsibilty whatsoever!')
print ('This script will take some time to fully complete')
print ('################################################################')
print ()
#
varRISK = input ('You accept all responsibilty when using this script yes|no: ')
if varRISK == 'yes':
    print ('continuing at your ouw risk')
else:
    exit()
#
print ('Prerequisites')
print ('-Windows 64 bit OS')
print ('-Nmap installed in the default folder')
print ('-Python 3.x installed')
print ()
print ('Tips')
print ('Ideally a VM with the Prerequisites installed would be snapshotted')
print ('before running the script. This will allow you to revert back and')
print ('start again. Also wipes any potential compromise')
print ()
print ('The script performs the following')
print ('-Pings an upstream device to ensure the firewall is passing ICMP')
print ('-Performs 4 NMAP scans (XMAS, FIN, NULL and UDP) on an upstream device')
print ('-Performs 1 URL check for Adult - playboy.com')
print ('-Pulls Malware Domain list from Malware Domains, parses it, removes duplicates,')
print ('-Pulls malicious URLS from VXVault')
print ('-Pulls SPAM and Other Domain, parses it, removes duplicates,')
print ()
print ('################################################################')
print ('################################################################')
print ('################################################################')
#######################################################################################################################
#ICMP Gateway Test
#######################################################################################################################
print ('The IP used below will be used for ICMP and NMAP')
varGW = input ('Enter IP address of upstream device beyond the Firepower: ')

varPING = os.system ('ping.exe -n 1 ' + varGW)
if varPING == 0:
    print ()
    print ('################################################################')
    print (varGW, 'is up  !!!!!!!!!!!!')
    print ('################################################################')
else:
    print ()
    print ('################################################################')
    print (varGW, 'is down  ..........')
    print ('################################################################')
#######################################################################################################################
#NMAP Portscan
#######################################################################################################################
print ()
print ('################################################################')
print ('NMAP Scans XMAS, FIN, NULL, and UDP will run!')
print ('################################################################')

varNMAPPATH = ('"c:\\Program Files (x86)\\Nmap\\nmap.exe"')

print ('Performing XMAS ...................')
varXMAS = os.system ('cmd /c ' + varNMAPPATH + ' -sX ' + varGW)
if varXMAS == 0:
    print ('################################################################')
    print (varGW, 'XMAS Scan Complete. Check for IPS for PSNG Alert!')
    print ('################################################################')
else:
    print ('Please ensure that nmap is installed in c:\\Program Files (x86)\\Nmap')

print ('Performing TCP FIN Scan ...................')
varFIN = os.system ('cmd /c ' + varNMAPPATH + ' -sF ' + varGW)
if varFIN == 0:
    print ('################################################################')
    print (varGW, 'TCP FIN Scan Complete. Check for IPS for PSNG Alert!')
    print ('################################################################')
else:
    print ('Please ensure that nmap is installed in c:\\Program Files (x86)\\Nmap')

print ('Performing TCP NULL Scan ...................')
varNULL = os.system ('cmd /c ' + varNMAPPATH + ' -sN ' + varGW)
if varNULL == 0:
    print ('################################################################')
    print (varGW, 'TCP NULL Scan Complete. Check for IPS for PSNG Alert!')
    print ('################################################################')
else:
    print ('Please ensure that nmap is installed in c:\\Program Files (x86)\\Nmap')

print ('Performing UDP Scan ...................')
varUDP = os.system ('cmd /c ' + varNMAPPATH + ' -sU ' + varGW)
if varUDP == 0:
    print ('################################################################')
    print (varGW, 'UDP Scan Complete. Check for IPS for PSNG Alert!')
    print ('################################################################')

else:
    print ('Please ensure that nmap is installed in c:\\Program Files (x86)\\Nmap')

print ()
print ('################################################################')
print ('All NMAP Scans Complete')
print ()
print ('If Firepower did not produce an alert then you most likely ')
print ('you have not enabled port scanning within network analysis policy')
print ('under settings - edit as desired but make sure to apply to an')
print ('access policy. Net Analysis details below')
print ('Enable - TCP, UDP, ICMP, IP')
print ('Scan Type - Portscan, Portsweep, Decoy PS, Distributed PS')
print ('Sensitivity Level = Medium')
print ('Detect Ack Scans')
print ()
print ('Details below on what IPS signatures need to be enabled')
print ('Enable all GID:122 IPS and set to drop and generate events')
print ('################################################################')

#######################################################################################################################
#Download EICAR
#######################################################################################################################

print ()
print ('################################################################')
print ('Pulling Eicar')

try:
    varEICAR = urllib.request.urlretrieve('http://www.eicar.org/download/eicar.com.txt', 'eircar.com.txt')
except (ConnectionResetError) as e:
    print ('Connection reset!')
except (urllib.request.URLError) as e:
    print ('URL Error. Perhaps URL has been changed')
else:
    print ('Downloaded Eicar!  Check Firepower!')
    print ()
    print ('################################################################')

#######################################################################################################################
#PULL MALWARE - Malware Zombies (marked as Malware in AMP Cloud for testing)
#######################################################################################################################
print ()
print ('################################################################')
print ('Pulling Zombies.pdf')

try:
    varZOMBIES = urllib.request.urlretrieve('http://www.cloudyip.net/AMP/Zombies.pdf', 'Zombies.pdf')
except ConnectionResetError as e:
    print ('Connection reset!')
except urllib.request.URLError as e:
    print ('URL Error. Perhaps URL has been changed')
else:
    print ('Downloaded Zombies!  Check FireSIGHT!')
    print ()
    print ('################################################################')

#######################################################################################################################
#Connect to Adult URL Category - this is to check that content filtering is enabled. 
#######################################################################################################################
print ()
print ('################################################################')
print ('Connect to Adult URL Category')

try:
    urllib.request.urlretrieve ('http://www.playboy.com')
except urllib.request.URLError as e:
    print ('DNS Lookup Failed!')
except NameError as e:
    print ('Name Error but keep going!!!')
except ConnectionResetError as e:
    print ('Connection Reset Error')
except TimeoutError as e:
    print ('Timed out but keep going in the name of security')
print ('Connected to an Adult Site - Check URL Cateogries!!!')
print ('More may pulled during malware domains check but look for ')
print ('playboy.com to validate this test')
print ('################################################################')

#######################################################################################################################
#PULL VX_Vault Sites
#######################################################################################################################
print ()
print ('################################################################')
print ('Pulling VX Vault - Ugly Sites')
print ('################################################################')

varVXVault = urllib.request.urlretrieve ('http://vxvault.net//URL_List.php', 'VXVault.txt')
with open('VXVault.txt','r') as f, open('VXVault_JM.txt','w') as f2:
    for x in f:
        if 'VX' not in x:
            f2.write(x.strip()+'\n')

uniqlines = set(open('VXVault_JM.txt').readlines())
clean = open('VXVault_JM.txt', 'w').writelines(set(uniqlines))

f = open('VXVault_JM.txt','r')
for line in f:
    try:
        #print (line)
        urllib.request.urlopen ((line), timeout=1)
    except urllib.request.URLError as e:
        print ('DNS Lookup Failed! Perhaps domain pulled')
    except NameError as e:
        print ('Name Error! To infinity an beyond!')
    except ConnectionResetError as e:
        print ('Connection Reset Error! Blocking')
    except TimeoutError as e:
        print ('Timed out but keep going in the name of security')
    except socket.timeout as e:
        print ('Socket Timeout - Moving on........')
    except Exception as e:
        print (e)
f.close()


#######################################################################################################################
#PULL MALWARE Sites
#######################################################################################################################
print ()
print ('################################################################')
print ('Pulling MALWARE Sites')
print ('################################################################')

varPULLMALWARE = urllib.request.urlretrieve ('http://www.malwaredomainlist.com/hostslist/hosts.txt', 'malware.txt')
with open('malware.txt','r') as f, open('malware_JM.txt','w') as f2:
    for x in f:
        if '#' not in x:
            f2.write(x.strip()+'\n')

with open ('malware_JM.txt', 'r') as f2, open('malware_JM3.txt', 'w') as f3:
	for line in f2:
		f3.write(line.replace('127.0.0.1  ', ''))
		
uniqlines = set(open('malware_JM3.txt').readlines())
clean = open('malware_JM3.txt', 'w').writelines(set(uniqlines))

f = open('malware_JM3.txt','r')
for line in f:
    try:
        #print (line)
        urllib.request.urlopen ('http://' + (line), timeout=1)
    except urllib.request.URLError as e:
        print ('DNS Lookup Failed! Perhaps domain pulled')
    except NameError as e:
        print ('Name Error! To infinity an beyond!')
    except ConnectionResetError as e:
        print ('Connection Reset Error! Blocking')
    except TimeoutError as e:
        print ('Timed out but keep going in the name of security')
    except socket.timeout as e:
        print ('Socket Timeout - Moving on........')
    except Exception as e:
        print (e)
f.close()


#######################################################################################################################
#PULL SPAM DOMAINS
#######################################################################################################################
print ()
print ('################################################################')
print ('Pulling SPAM and Other sites from Joewein')
print ('################################################################')

varPULLSPAM = urllib.request.urlretrieve ('http://www.joewein.net/dl/bl/dom-bl.txt', 'spam.txt')
with open('spam.txt','r') as f, open('spam_JM.txt','w') as f2:
    for x in f:
        if '#' not in x:
            f2.write(x.strip()+'\n')

uniqlines = set(open('spam_JM.txt').readlines())
clean = open('spam_JM.txt', 'w').writelines(set(uniqlines))

f = open('spam_JM.txt','r')
for line in f:
    try:
        #print (line)
        urllib.request.urlopen ('http://' + (line), timeout=1)
    except urllib.request.URLError as e:
        print ('DNS Lookup Failed! Perhaps domain pulled')
    except NameError as e:
        print ('Name Error! To infinity an beyond!')
    except ConnectionResetError as e:
        print ('Connection Reset Error! Blocking')
    except TimeoutError as e:
        print ('Timed out but keep going in the name of security')
    except socket.timeout as e:
        print ('Socket Timeout - Moving on........')
    except Exception as e:
        print (e)
f.close()

print ('################################################################')
print ('################################################################')
print ('################################################################')
print ()
print ('Connected to Dirty Sites')
print ('Consider wipping or reverting snap of this dirty box!!!')
print ()
print ('################################################################')
print ('################################################################')
print ('################################################################')
print ('################################################################')

#####################################
#Cleaning up
####################################
os.remove('spam.txt')
os.remove('spam_JM.txt')
os.remove('malware.txt')
os.remove('malware_JM.txt')
os.remove('malware_JM3.txt')
os.remove('Zombies.pdf')
os.remove('VXVault.txt')
os.remove('VXVault_JM.txt')
print ()
print ('################################################################')
print ('Removing VXVault.txt temp file!')
print ('Removing VXVault_JM.txt temp file!')
print ('Removing phish.txt temp file!')
print ('Removing phish_JM.txt temp file!')
print ('Removing malware.txt temp file!')
print ('Removing malware_JM.txt temp file!')
print ('Removing malware_JM3.txt temp file!')
print ('Removing Zombies.pdf!')
print ('Thats it. Check FireSIGHT for events and have fun!')
print ('################################################################')

exit()
