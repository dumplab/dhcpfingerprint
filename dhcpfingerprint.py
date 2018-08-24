#!/usr/bin/python
"""Basic DHCP Fingerprinting using python, scapy

This script captures DHCP traffic, could identifiy Device type, vendor and OS and updates known NeDi nodes. Requires scapy and mysqlconnector
"""

__author__    = "dumplab"
__copyright__ = "2018 dumplab"
__license__   = "MIT"
__version__   = "1.0"

## Import Scapy module
from scapy.all import *
import mysql.connector as mariadb
import sys;
import re

# enter capture nic and instead 10.10.10.10 your dhcp server ip as a capturefilter
captureInterface = "eth0"
captureFilter    = "host 10.10.10.10 and port 67"
debug            = False

# database
fpDB = {
        '1,121,33,3,6,28,51,58,59':                                ['Android 2.2'],
        '1,121,33,3,6,15,28,51,58,59,119':                         ['Android 2.3'],
        '1,33,3,6,15,28,51,58,59':                                 ['Android 4.1'],
        '1,3,6,15,26,28,51,58,59,43':                              ['Android 8.0'],
        '1,2,3,15,6,12,44':                                        ['Apple Airport'],
        '1,28,3,6,15':                                             ['Apple Airport'],
        '28,3,6,15':                                               ['Apple Airport'],
        '1,3,6,15,119,78,79,95,252' :                              ['Apple iOS'],
        '1,3,6,15,119,252' :                                       ['Apple iOS'],
        '1,3,6,15,119,252,46,208,92' :                             ['Apple iOS'],
        '1,3,6,15,119,252,67,52,13' :                              ['Apple iOS'],
        '1,121,3,6,15,119,252' :                                   ['Apple iOS'],
        '1,3,6,15,112,113,78,79,95' :                              ['Apple Mac OS X'],
        '1,3,6,15,112,113,78,79,95,252' :                          ['Apple Mac OS X'],
        '3,6,15,112,113,78,79,95,252' :                            ['Apple Mac OS X'],
        '3,6,15,112,113,78,79,95' :                                ['Apple Mac OS X'],
        '3,6,15,112,113,78,79,95,44,47' :                          ['Apple Mac OS X'],
        '1,3,6,15,112,113,78,79,95,44,47' :                        ['Apple Mac OS X'],
        '1,3,6,15,112,113,78,79' :                                 ['Apple Mac OS X'],
        '1,3,6,15,119,95,252,44,46,101' :                          ['Apple Mac OS X'],
        '1,3,6,15,119,112,113,78,79,95,252' :                      ['Apple Mac OS X'],
        '3,6,15,112,113,78,79,95,252,44,47' :                      ['Apple Mac OS X'],
        '1,3,6,15,112,113,78,79,95,252,44,47' :                    ['Apple Mac OS X'],
        '1,3,12,6,15,112,113,78,79' :                              ['Apple Mac OS X'],
        '1,121,3,6,15,119,252,95,44,46' :                          ['Apple macOS'],
        '60,43' :                                                  ['Apple Mac OS X'],
        '43,60' :                                                  ['Apple Mac OS X'],
        '1,3,6,15,119,95,252,44,46,47' :                           ['Apple Mac OS X'],
        '1,3,6,15,119,95,252,44,46,47,101' :                       ['Apple Mac OS X'],
        '1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42' : ['Generic Linux'],
        '1,121,33,3,6,12,15,28,42,51,54,58,59,119' :               ['Generic Linux'],
        '3,6,12,15,17,23,28,29,31,33,40,41,42,119' :               ['Generic Linux'],
        '1,3,6,12,15,23,28,29,31,33,40,41,42' :                    ['Generic Linux'],
        '3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,200,44' :        ['Generic Linux'],
        '1,3,6,12,15,23,28,29,31,33,40,41,42,9,7,200,44' :         ['Generic Linux'],
        '1,28,2,3,15,6,12,121,249,252,42' :                        ['Generic Linux'],
        '1,121,33,3,6,12,15,26,28,42,51,54,58,59,119' :            ['Generic Linux'],
        '1,15,3,6,44,46,47,31,33,249,43' :                         ['Microsoft Windows XP'],
        '1,15,3,6,44,46,47,31,33,249,43,252' :                     ['Microsoft Windows XP'],
        '1,15,3,6,44,46,47,31,33,249,43,252,12' :                  ['Microsoft Windows XP'],
        '15,3,6,44,46,47,31,33,249,43' :                           ['Microsoft Windows XP'],
        '15,3,6,44,46,47,31,33,249,43,252' :                       ['Microsoft Windows XP'],
        '15,3,6,44,46,47,31,33,249,43,252,12' :                    ['Microsoft Windows XP'],
        '28,2,3,15,6,12,44,47' :                                   ['Microsoft Windows XP'],
        '1,15,3,6,44,46,47,31,33,121,249,43,252' :                 ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43' :                     ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,32,176,67' :         ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,176,67' :            ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,252' :                 ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,195' :                 ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,112,64' :            ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,128,64' :            ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,168,112,64]' :       ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,188,67' :            ['Microsoft Windows 7'],
        '1,15,3,6,44,46,47,31,33,121,249,43,0,64,112' :            ['Microsoft Windows 7'],
        '1,3,6,15,31,33,43,44,46,47,121,249,252' :                 ['Microsoft Windows 10'],
        '1,15,3,6,44,46,47,31,33,43' :                             ['Microsoft Windows 2000'],
        '1,15,3,6,44,46,47,31,33,43,252' :                         ['Microsoft Windows 2000'],
        '1,15,3,6,44,46,47,31,33,43,252,12' :                      ['Microsoft Windows 2000'],
        '15,3,6,44,46,47,31,33,43' :                               ['Microsoft Windows 2000'],
        '15,3,6,44,46,47,31,33,43,252' :                           ['Microsoft Windows 2000'],
        '1,15,3,6,44,46,47,31,33,43,77' :                          ['Microsoft Windows ME'],
        '15,3,6,44,46,47,31,33,43,77' :                            ['Microsoft Windows ME'],
        '1,3,6,15,44,46,47,57' :                                   ['Microsoft Windows 98'],
        '15,3,6,44,46,47,43,77' :                                  ['Microsoft Windows 98SE'],
        '1,15,3,6,44,46,47,43,77' :                                ['Microsoft Windows 98SE'],
        '15,3,6,44,46,47,43,77,252' :                              ['Microsoft Windows 98SE'],
        '1,15,3,6,44,46,47,43,77,252' :                            ['Microsoft Windows 98SE'],
        '1,3,15,6,44,46,47' :                                      ['Microsoft Windows 95'],
        '1,2,3,6,12,15,26,28,85,86,87,88,44,45,46,47,70,69,78,79' :['Microsoft Windows NT 4'],
        '1,15,3,44,46,47,6' :                                      ['Microsoft Windows NT 4'],
        '1,28,2,3,15,6,12,40,41,42' :                              ['RedHat or Fedora Linux'],
        '28,2,3,15,6,12,40,41,42' :                                ['RedHat or Fedora Linux'],
        '1,28,2,3,15,6,12,40,41,42,26,119' :                       ['RedHat or Fedora Linux'],
        '1,28,2,3,15,6,12,40,41,42,26' :                           ['RedHat or Fedora Linux'],
        '1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,42' :        ['RedHat or CentOS Linux'],
        '53,54,1,51,52,3,6,31' :                                   ['VxWorks'],
}

# callback function to process DHCP messages
def procdhcp(pkt):
	# BOOTP op 1= discover/request, 2 = reply
	if pkt[BOOTP].op==1:
		if debug:
			pkt.show()
		# go throupgh options
		tmpOptions = pkt[DHCP].options
		for dhcpOptions in tmpOptions:
			# looking for tuple ('param_req_list', '\x01\x0f\x03\x06,./\x1f!y\xf9+\xfc')
			if re.search("param_req_list",str(dhcpOptions)):
				# get Client hardware address
				tmpsrcMac = str(pkt[BOOTP].chaddr).encode("HEX")
				srcMac    = tmpsrcMac[:12]
				params    = str(dhcpOptions[1]).encode("HEX")
				# create empty string
				opt55     = "" 
				for i in xrange(0,len(params),2):
					byte = params[i:i+2]
					# conc string, hex to int
					if i==0:
						opt55 = str(int(byte, 16))
					else:
						opt55 += "," + str(int(byte, 16))

				os = fpDB.get(opt55,[])
				if not any(os):
					result = "none"
				else:
#					print("OS: " + str(os) + " updating NeDi")
					result = str(os[0])
					query = "UPDATE nodarp SET srvos='" + result + "' WHERE mac='" + srcMac + "'"
#					print(query)
					try:
						cursor.execute(query)
					except mariadb.Error as error:
						print("Error: {}".format(error))
					mariadb_connection.commit()
				print("MAC:" + srcMac + " Params:" + str(opt55) + " Fingerbank:" + result)

print("********************************************************")
print("* Starting DHCP Fingerprint                            *")
print("********************************************************")
print("Capturing on Interface: " +captureInterface)
print("Using capture filter:   " + captureFilter)
print("********************************************************")
print("Connecting to NeDi database ...")
try:
	mariadb_connection = mariadb.connect(host="host.acme.xy", user="nediuser", password="nedipassword", database="nedi")
except:
	print("Could not connect to NeDi database ... does not make sense to continue")
	sys.exit(0)

print("OK ... processing captured DHCP requests")
cursor = mariadb_connection.cursor()

# call scapy sniff function
pkts = sniff(iface=captureInterface,filter=captureFilter, count=0,prn=procdhcp, store=0)

mariadb_connection.close()
