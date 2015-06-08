#!/usr/bin/python
#coding=utf8

from scapy.all import *
from pyscutclient_func import gen_checksum
import os
import time
import argparse

#从用户输入获取username password iface
parser = argparse.ArgumentParser(description='802.1x Auth Tool for SCUT')
parser.add_argument('--username', default='')
parser.add_argument('--password', default='')
parser.add_argument('--iface', default='eth0')
args = parser.parse_args()



SAVEDUMP = 0   #dump pcap file

#一些常量
EAPOL_ASF = 4
EAPOL_KEY = 3
EAPOL_LOGOFF = 2
EAPOL_START = 1
EAPOL_EAP_PACKET = 0

EAP_FAILURE = 4
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_TYPE_ID = 1
EAP_TYPE_MD5 = 4

#各种信息
username = args.username
password = args.password
conf.iface = args.iface
MY_INTERFACE = conf.iface
MY_IP = os.popen("ifconfig %s | grep 'inet' | grep -v 'inet6' | awk '{print $2}' | cut -d: -f2" %MY_INTERFACE).read()[:-1]
#获取带inet的行，去掉带inet6的行，只要第2块，对':'进行分割，取分割后的第2个，最后还带一个'\n'，去掉
MY_NETMASK = os.popen("ifconfig %s | grep 'inet' | grep -v 'inet6' | awk '{print $4}' | cut -d: -f2" %MY_INTERFACE).read()[:-1]
MY_BCAST = os.popen("ifconfig %s | grep 'inet' | grep -v 'inet6' | awk '{print $3}' | cut -d: -f2" %MY_INTERFACE).read()[:-1]
MY_GATEWAY = MY_BCAST[:-1] + str(int(MY_BCAST[-1])-1)   #在ubuntu系列下似乎是网关等于广播最后一位减1
MY_DNS = '114.114.114.114'  #DNS似乎不影响认证
MY_MAC = os.popen("ifconfig %s| awk '{print $5}' | head -1" %MY_INTERFACE).read()[:-1]
DSTMAC = '01:80:C2:00:00:03'

#校验码的生成
checkinfo = [0x00,0x00,0x13,0x11,0x00]
for s in MY_IP.split('.'):
	checkinfo.append(int(s))
for s in MY_NETMASK.split('.'):
	checkinfo.append(int(s))
for s in MY_GATEWAY.split('.'):
	checkinfo.append(int(s))
for s in MY_DNS.split('.'):
	checkinfo.append(int(s))
checkinfo.append(0x00)
checkinfo.append(0x00)
checksum = gen_checksum(checkinfo)



pkts=[]  #捕获的包放到列表，用于dump pcap

#下面是构造的包
p_start = Ether(src=MY_MAC, dst=DSTMAC, type=0x888e)/EAPOL(version=1,type=1,len=0)/Padding(load=checksum + '\x00\x00\x13\x118021x.exe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0037500\x00\x00\x13\x11\x00(\x1a(\x00\x00\x13\x11\x17"\x91baeaeaich\x95if\x94\x94c\x95`h\x94h\x94hc\x96\x91a\x9a\xa7\x94\x9f\xab\x00\x00\x13\x11\x18\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

p_identity = Ether(src=MY_MAC, dst=DSTMAC, type=0x888e)/EAPOL(version=1, type=0, len=44)/EAP(code=2, type=1, id=1, len=44)/Raw(load='%s#0%s#4.1.5#EXT\x00' %(username,MY_IP))/Padding(load=checksum + '\x00\x00\x13\x118021x.exe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0037500\x00\x00\x13\x11\x00(\x1a(\x00\x00\x13\x11\x17"\x91baeaeaich\x95if\x94\x94c\x95`h\x94h\x94hc\x96\x91a\x9a\xa7\x94\x9f\xab\x00\x00\x13\x11\x18\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

p_md5 = Ether(src=MY_MAC, dst=DSTMAC, type=0x888e)/EAPOL(version=1, type=0, len=61)/EAP(code=2, type=4, id=2, len=61)/Raw(load='\x10%s\x00\x00\x00\x00%s#0%s#4.1.5#EXT\x00' %(username,password,MY_IP))/Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

p_logoff = Ether(src=MY_MAC, dst=DSTMAC, type=0x888e)/EAPOL(version=1, type=2, len=0)/Padding(load=checksum + '\x00\x00\x13\x118021x.exe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0037500\x00\x00\x13\x11\x00(\x1a(\x00\x00\x13\x11\x17"\x91baeaeaich\x95if\x94\x94c\x95`h\x94h\x94hc\x96\x91a\x9a\xa7\x94\x9f\xab\x00\x00\x13\x11\x18\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


def send_start():
	print 'SCUTclient: Start.'
	sendp(p_start, verbose=0)   #静默发送

def send_identity():
	sendp(p_identity, verbose=0)
	print 'SCUTclient: Respond Identity.'

def send_md5():
	sendp(p_md5, verbose=0)
	print 'SCUTclient: Respond MD5-Challenge.'

def send_logoff():
	sendp(p_logoff, verbose=0)
	print 'SCUTclient: Logoff.'

def sniff_handler(pkt):
	pkts.append(pkt)
	try:
		if pkt.haslayer(EAP) and (pkt[EAP].code == EAP_REQUEST) and (pkt[EAP].type == EAP_TYPE_ID):   #避免pkt[EAP]不存在时出错
			print 'Server: Request Identity!'
			send_identity()
		elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_REQUEST) and (pkt[EAP].type == EAP_TYPE_MD5):
			print 'Server: Request MD5-Challenge!'
			send_md5()
		elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_SUCCESS):
			print 'Server: Success.'
		elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_FAILURE):
			print 'Server: Failure.\nWill retry after 5 seconds.\n'
			time.sleep(5)
			send_start()
	except BaseException, e:  #捕获所有异常
		print 'Error:', e




if __name__ == '__main__':
	if not username:
		print '\nUsage: sudo python pyscutclient --username [username] --password [password] --iface [iface]'
		exit(1)
	if not password:
		password = username
	try:
		print '\n'
		print '='*60
		print '\n         pyscutclient by 7forz\n'
		print '  Project page at https://github.com/7forz/pyscutclient'
		print '='*60
		print '\nConfirm your MAC: %s' %MY_MAC
		print 'Confirm your IP: %s' %MY_IP
		print 'Confirm your Netmask: %s' %MY_NETMASK
		print 'Confirm your Gateway: %s\n' %MY_GATEWAY
		
		
		send_start()
		sniff(filter="(ether proto 0x888e) and (ether host %s)" %MY_MAC, prn = sniff_handler)  #只捕获自己的MAC的802.1x，捕获到的包给handler处理
	except KeyboardInterrupt, e:
		print e, '停止'
	finally:
		send_logoff()
		if SAVEDUMP:
			wrpcap('pyscutclient.cap', pkts)
