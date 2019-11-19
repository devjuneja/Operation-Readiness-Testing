#!/usr/bin/python2

import sys, os, glob

for i in glob.glob("/home/libs/*"):
	sys.path.append(os.path.abspath(i))

# csv, file

#import paramiko
import pexpect 
from pexpect import EOF
#import pxssh
from openpyxl import Workbook

import getpass, re
from datetime import datetime


'''
	Finds system username, full name and user ID.
	
	return:
		(username, full name, uid)
		None - if not found
'''

def findUserFullNameAndID():
	username = getpass.getuser()
	
	with open('/etc/passwd', 'r') as file:
		for line in file:
			if re.match('^%s:.*' % username, line):
				l = re.split(':', line)
				return (username, l[4], l[2])
	
	return (None, None, None)

	
	


# ask for input file
if len(sys.argv) > 1:
	infile = sys.argv[1]
else:
	infile = "dev_to_check.txt"
	infile = raw_input("Input file [%s]: " % infile) or infile

print('')
print('Choosed file: %s.' % infile)
print('')

uid, fullName, username = findUserFullNameAndID()

username = raw_input("login [%s]: " % username) or username

password = getpass.getpass('password: ')

print('')


outfilename = "%s_ort" % datetime.now().strftime("%Y%m%d%H%M%S")

print('Output files prefix: %s' % outfilename)

try:
	with open(infile) as f:
		with open(outfilename + '.txt', 'w') as outfile:
			outfile.write("ip,icmp,reachable,tacacs,location,comment,shinvisn\n")
			outfile.flush()
			
			outfileexcel = Workbook()
			outfileexcelws = outfileexcel.active
			outfileexcelws.title = infile

			outfileexcelws.append(['ip', 'icmp', 'reachable', 'tacacs', 'location', 'comment', 'sh inv', 'sh inv | i SN' ])

			for ip in f:
				ip = ip.rstrip('\n').rstrip('\r')
						
				# check if line contains valid IP address
				if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip) is None:
					continue
				
				comment = ''
				icmp = ''
				reachable = ''
				tacacs = ''
				location = ''
				shinv = ''
				shinvisn = ''
				
				print('%s ...' % ip)

				
				try:
					#ping
					child = pexpect.spawn('ping -W 3 -c 3 %s' % (ip), timeout=15)
					
					index = child.expect(['3 packets transmitted'])
						
					if index != 0:
						icmp = 'unknown'
					else:
						index = child.expect(['0 received', '1 received', '2 received', '3 received'])
						
						if index == 0:
							icmp = 'no'
						elif index == 1:
							icmp = 'recieved 1/3'
						elif index == 2:
							icmp = 'recieved 2/3'
						elif index == 3:
							icmp = 'yes'
					
					
					child.close()
					
					# ssh
					child = pexpect.spawn('ssh -o StrictHostKeyChecking=no -l %s %s' % (username, ip), timeout=15)
					try:
						# add cisco controller support
						while True:
							index = child.expect(['[Pp]assword:', '[Uu]ser:'], timeout=60)
							if index == 0:
								child.sendline(password)
								break
								
							if index == 1:
								child.sendline(username)
							
							
							
								
					except pexpect.EOF:
						# connection refused?
						print("SSH EOF")
						comment = child.before
						print(comment)
						reachable = 'no/eof'
						tacacs = 'no/eof'
						#icmp = 'no/eof'
						outfile.write("%s,%s,%s,%s,%s,%s,%s\n" % (ip, icmp, reachable, tacacs, location, shinvisn, comment.replace('\n', ' ').replace('\r', ' ')))
						outfile.flush()
						
						outfileexcelws.append([ip, icmp, reachable, tacacs, location, comment, shinv, shinvisn])
						outfileexcel.save(outfilename + ".xlsx")

						child.close()
						continue
					
					except pexpect.TIMEOUT:
						print("SSH TIMEOUT")
						comment = child.before
						print(comment)
						reachable = 'no/timeout'
						tacacs = 'no/timeout'
						#icmp = 'no/timeout'
						outfile.write("%s,%s,%s,%s,%s,%s,%s\n" % (ip, icmp, reachable, tacacs, location, shinvisn,comment.replace('\n', ' ').replace('\r', ' ')))
						outfile.flush()
						
						outfileexcelws.append([ip, icmp, reachable, tacacs, location, comment, shinv, shinvisn])
						outfileexcel.save(outfilename + ".xlsx")

						child.close()
						continue

					hostname_pattern = '[a-zA-Z0-9\-_\.()]{5,}#'
					hostname_pattern_wlc = '[a-zA-Z0-9\-_\.()]{5,} >'
					
					index = child.expect(['[Pp]assword:', hostname_pattern, 'menu TS prompt', '[Uu]ser:', hostname_pattern_wlc, 'Cisco Nexus Operating System '], timeout=60)
					#

					if index == 0 or index == 3:
						print('bad pass')

						reachable = 'yes'
						tacacs = 'no'
						comment = 'username/password incorrect'
						child.close()
					elif index == 1 or index == 2:
						if index == 2:
							child.sendline('e')
							child.expect(hostname_pattern)
							
						print('Logged in.')
						reachable = 'yes'
						tacacs = 'yes'
						
						# need to obtain hostname 
						'''child.sendline('show runn | i hostname')
						child.expect(hostname_pattern)
						host = child.before.replace('\n', '').replace('\r', '').replace('show runn | i hostname', '')
						if re.match("hostname .*", host):
							host = host.replace("hostname ", "")
							hostname_pattern = "%s#" % host
							hostname_pattern_wlc = "%s >" % host
						else:
							print("unable to determine hostname, using RegExp")'''
						

						child.sendline('show ap summary')
						child.expect(hostname_pattern)
						shinvisn = child.before.replace('show ap summary', '')
						
						child.sendline('exit')
						child.close()
					elif index == 4:
						# WLC
						print('Logged in.')
						reachable = 'yes'
						tacacs = 'yes'

						child.sendline('config paging disable')
                                                child.expect(hostname_pattern_wlc)

                                                child.sendline('show cdp')
                                                child.expect(hostname_pattern_wlc)
                                                location = child.before.replace('\n', '').replace('\r', '').replace('show cdp', '')

                                                child.sendline('show ap summary')
                                                child.expect(hostname_pattern)
                                                shinv = child.before.replace('show ap summary', '')


                                                child.sendline('logout')
                                                child.close()

				except pexpect.TIMEOUT:
					print("SSH TIMEOUT")
					comment = child.before
					print(comment)
					reachable = 'no/timeout'
					tacacs = 'no/timeout'
					icmp = 'no/timeout'
					outfile.write("%s,%s,%s,%s,%s,%s,%s\n" % (ip, icmp, reachable, tacacs, location, shinvisn ,comment.replace('\n', ' ').replace('\r', ' ')))
					outfile.flush()
					
					outfileexcelws.append([ip, icmp, reachable, tacacs, location, comment, shinv, shinvisn])
					outfileexcel.save(outfilename + ".xlsx")
					
					child.close()
				
				#print("\n\n")
				#exit(1)

finally:
	print('\n###########################################')
	print('Input file: %s.' % infile)
	print('Output files prefix: %s' % outfilename)
	print('###########################################\n\n')
