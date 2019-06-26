#!/usr/bin/python
"""Basic DHCP Fingerprinting using scapy

This script captures DHCP traffic, could identifiy Device type, vendor and OS and updates known NeDi nodes. Requires scapy and mysqlconnector
"""

__author__    = "dumplab"
__copyright__ = "2018 dumplab"
__license__   = "MIT"
__version__ = "1.1"

## Import Scapy module
from scapy.all import *
import mysql.connector as mariadb
import re, time


# enter capture nic and instead 10.10.10.10 your dhcp server ip as a capturefilter
captureInterface = "eth0"
captureFilter = "host 10.10.10.10 and port 67"
# prepare empty list to hold objects
dhcprequests     = []
dhcpmaxqueue     = 200 # how much transactions in queue before we save into db
dhcpmaxtime      = 10  # OR seconds we wait between saving queue into db
useDatabase      = True # false = dont use database, just run output
debug            = False
# internals
timer            = int(time.time())
cursornedi       = None

class cDHCPtransaction(object):
	"""Represents a DHCP transaction"""

	def __init__(self,txid,mac="",ip="",relayagentip="",leasetime=0,lastdhcpack=0,dhcpfingerprint="",dhcpvendor="",deviceclass="",hostname="",hostos="",internalts=0):
		"""Set default attribute values only

		Keyword arguments:
		txid -- transaction id (mandatory integer)
		mac -- Client MAC address (default "")
		ip -- client ip address (default "")
		relayagentip -- ip of relay agent (default "")
		leasetime -- submited leasetime (default 0)
		lastdhcpack -- last timestamp of dhcp ack (default 0)
		dhcpfingerprint -- dhcpfingerprint
		dhcpvendor -- dehcp vendor
		deviceclass -- this is internal only
		hostname -- hostname
		"""
		self.txid            = txid
		self.mac             = mac
		self.ip              = ip
		self.relayagentip    = relayagentip
		self.leasetime       = leasetime
		self.lastdhcpack     = lastdhcpack
		self.dhcpfingerprint = dhcpfingerprint
		self.dhcpvendor      = dhcpvendor
		self.deviceclass     = deviceclass
		self.hostname        = hostname
		self.hostos          = hostos
		self.internalts      = internalts # an internal ts to delete obsolete requests without an reply

# database
fpDB = {
	'1,33,3,6,15,26,28,51,58,59':                              ['Android OS'],
	'1,121,33,3,6,28,51,58,59':                                ['Android 2.2'],
	'1,121,33,3,6,15,28,51,58,59,119':                         ['Android 2.3'],
	'1,33,3,6,15,28,51,58,59':                                 ['Android 4.1'],
	'1,3,6,15,26,28,51,58,59,43':                              ['Android 7.x or 8.0'],
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
#	'1,6,15,44,3,7,33,150,43':                                 ['Cisco Wireless Access Point'],
#	'1,3,6,15,28,33,43,44,58,59' :                             ['HP iLO Agent'],
#	'1,2,3,4,6,15,28,33,42,43,44,58,59,100,101' :              ['HP iLO Agent'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42' : ['Generic Linux'],
	'1,121,33,3,6,12,15,28,42,51,54,58,59,119' :               ['Generic Linux'],
	'3,6,12,15,17,23,28,29,31,33,40,41,42,119' :               ['Generic Linux'],
	'1,3,6,12,15,23,28,29,31,33,40,41,42' :                    ['Generic Linux'],
	'3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,200,44' :        ['Generic Linux'],
	'1,3,6,12,15,23,28,29,31,33,40,41,42,9,7,200,44' :         ['Generic Linux'],
	'1,28,2,3,15,6,12,121,249,252,42' :                        ['Generic Linux'],
	'1,121,33,3,6,12,15,26,28,42,51,54,58,59,119' :            ['Generic Linux'],
	'1,28,2,3,15,6,12' :                                       ['Generic Linux Synology'],
	'1,3,6,12,15,17,23,28,29,31,33,40,41,42,44' :              ['Generic Linux Synology'],
	'1,3,28,6' :                                               ['Generic Linux DPC'],
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
	'1,3,6,12,15,42,43,50,51,53,54,56,57,58,59' :              ['NetApp ONTAP'],
	'1,28,2,3,15,6,12,40,41,42' :                              ['RedHat or Fedora Linux'],
	'28,2,3,15,6,12,40,41,42' :                                ['RedHat or Fedora Linux'],
	'1,28,2,3,15,6,12,40,41,42,26,119' :                       ['RedHat or Fedora Linux'],
	'1,28,2,3,15,6,12,40,41,42,26' :                           ['RedHat or Fedora Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3' :                   ['RedHat or CentOS Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,42' :        ['RedHat or CentOS Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,42' :     ['Scientific Linux'],
	'1,28,2,3,15,6,119,12,44,47,26,121,42,121,249,33,252,42' : ['Kali Linux'],
	'53,54,1,51,52,3,6,31' :                                   ['VxWorks'],
}

# callback function to process DHCP
def procdhcp(pkt):
	global dhcprequests
	global timer
	global cursornedi

	opt55 = hostos = hostname = dhcpvendor = deviceclass = ""
	# BOOTP op 1= discover/request, 2 = reply
	if pkt[BOOTP].op==1:
		if debug:
			pkt.show()
		# get transaction id
		txid = int(pkt[BOOTP].xid)
		# go throupgh options
		tmpOptions = pkt[DHCP].options
		for dhcpOptions in tmpOptions:
			# looking for tuple ('param_req_list', '\x01\x0f\x03\x06,./\x1f!y\xf9+\xfc')
			if re.search("param_req_list",str(dhcpOptions)):
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
				# compare with fingerbank
				os = fpDB.get(opt55,[])
				if not any(os):
					hostos = ""
				else:
					hostos = str(os[0])
			# looking for tuple ('hostname', 'mylinux')
			if re.search("hostname",str(dhcpOptions)):
				#get message type
				hostname = str(dhcpOptions[1])

		# get Client hardware address
		tmpsrcMac = str(pkt[BOOTP].chaddr).encode("HEX")
		srcMac    = tmpsrcMac[:12]
		# get ip
		ip   = str(pkt[BOOTP].ciaddr)
		# get relay ip
		rip  = str(pkt[BOOTP].giaddr)
		new = True
		for myRequest in dhcprequests:
			if txid==myRequest.txid:
				new = False
				# update
				myRequest.hostname = hostname
				if hostos <> "":
					myRequest.hostos   = hostos
				if str(opt55) <> "":
					myRequest.dhcpfingerprint = str(opt55)
		# we only add if the client requested parameters
		if new==True and opt55<>"":
			# we got a dhcp transaction, create object and add to list
			dhcprequests.append(cDHCPtransaction(txid,srcMac,ip,rip,0,0,str(opt55),dhcpvendor,deviceclass,hostname,hostos,time.time()))

	# BOOTP op 2 = reply
	if pkt[BOOTP].op==2:
		leasetime = 0
		if debug:
			pkt.show()
		# go throupgh options
		gotAck = False
		# get transaction id
		txid = int(pkt[BOOTP].xid)
		# go throupgh options
		tmpOptions = pkt[DHCP].options
		for dhcpOptions in tmpOptions:
			if re.search("message-type",str(dhcpOptions)):
				# message-type 2 = OFFER
				# message-type 5 = ACK
				# message-type 6 = NAK
				#get message type
				if dhcpOptions[1]==5:
					gotAck = True
				if dhcpOptions[1]==6:
					for myRequest in dhcprequests:
						if txid==myRequest.txid:
							print("Got NAK delete " + str(myRequest.txid))
							# delete object and clean in list
							dhcprequests.remove(myRequest)
							del myRequest
			if re.search("lease_time",str(dhcpOptions)):
				leasetime = int(dhcpOptions[1])

		# only update on ACK from DHCP Server
		if gotAck:
			# get Client hardware address
			tmpsrcMac = str(pkt[BOOTP].chaddr).encode("HEX")
			srcMac    = tmpsrcMac[:12]
			# get ip
			ip   = str(pkt[BOOTP].ciaddr)
			if re.search("^0.0.0.0$",ip):
				ip = str(pkt[BOOTP].yiaddr)
			# get relay ip
			rip  = str(pkt[BOOTP].giaddr)
			new = True
			for myRequest in dhcprequests:
				#if re.search("^" + str(txid) + "$",str(myRequest.txid)):
				if txid==myRequest.txid:
					# update
					myRequest.mac          = srcMac
					myRequest.ip           = ip
					myRequest.relayagentip = rip
					myRequest.leasetime    = leasetime
					myRequest.lastdhcpack  = int(time.time())
					print("Got an ACK. Updated Transaction ID " + str(txid) + " IP:" + ip + " Relay:" + rip + " MAC:" + srcMac + " Hostname: " + myRequest.hostname + " LeaseTime: " + str(leasetime) + " Params:" + myRequest.dhcpfingerprint + " Fingerbank:" + myRequest.hostos)
			# lease time of 0 means there was no leasetime information from dhcp server request was inform

	# *****************************************
	# * process queue, update remote database *
	# *****************************************
	if (len(dhcprequests) >= dhcpmaxqueue or (timer+dhcpmaxtime < int(time.time()))):
		print("processing queue .... " + str(len(dhcprequests)) + " objects") # more than " + str(dhcpmaxqueue) + " dhcprequests queue or " + str(dhcpmaxtime) + "s")
		# timer to measure the time we need to flush the queue to the database
		mm = time.time()
		for myRequest in dhcprequests:
			release = False
			# see if the ACK timestamp was updated, indicates there was a successfully transaction
			if myRequest.lastdhcpack>0:
				print("Release " + str(myRequest.txid))
				release = True
			else:
				if myRequest.internalts+5 < int(time.time()):
					print("Released " + str(myRequest.txid)+ " no answer within 5s")
					dhcprequests.remove(myRequest)
					del myRequest
				else:
					print("Not Released no answer so far " + str(myRequest.txid))
					
			if release==True:
				if useDatabase:
					# update NeDi
					cursornedi.execute("UPDATE nodarp SET srvos='" + myRequest.hostos + "' WHERE mac='" + myRequest.mac + "'")
					mariadb_connection_ne.commit()

				dhcprequests.remove(myRequest)
				del myRequest

		# reset timer
		timer = int(time.time())
		# measurement
		xx = time.time() - mm
		print("Objects remaining in queue:" + str(len(dhcprequests)) + " processing queue took " + str(xx) + "s" )


print("********************************************************")
print("* Starting DHCP Fingerprint                            *")
print("********************************************************")
print("* Capture Interface: " +captureInterface)
print("* Capture filter:    " + captureFilter)
print("* DB Update:         >= " + str(dhcpmaxqueue) + " in queue or every " + str(dhcpmaxtime) + "s")
print("********************************************************")
mariadb_connection_ne = None
if useDatabase:
	try:
		mariadb_connection_ne = mariadb.connect(host="host.acme.xy", user="nediuser", password="nedipassword", database="nedi")
	except:
		print("Could not connect to NeDi database ... does not make sense to continue")
		sys.exit(0)
	cursornedi   = mariadb_connection_ne.cursor()

print("OK ... processing captured DHCP requests")

# call scapy sniff function
pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procdhcp, store=0)

mariadb_connection_ne.close()
