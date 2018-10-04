#!/usr/bin/python
from scapy.all import *
import argparse
import sys,json
conf.verb=0

#
# Example of input file
#[{"host":"192.168.207.41", "ports": "53-60", "udp": true, "icmp": true},
#  {"host":"192.168.207.42", "ports": "23-25", "udp": false, "icmp": false},
#  {"host":"192.168.207.41", "ports": "23-25", "udp": false, "icmp": false}
#]
#

# Prints the results in either html or text format
def printresults(host,port,udp,results,printhtml):
    if printhtml:
    	print("<div><p><b>Host: </b>"+host+"</p><p><b>Port: </b>"+str(port)+"</p><p><b>UDP: </b>"+str(udp)+"</p><p><b>Results: </b>"+results+"</p></div><br>")
    else:
	print(host+" "+str(port)+" "+results)

# scans each tcp or udp port
def portscan(host,port,udp,printhtml):
    ip = IP(dst=host)
    prot=""
    if not udp:
        prot=TCP(dport=int(port),flags='S',seq=1000)
    else:
        prot=UDP(dport=int(port))
    SYN_out=sr1(ip/prot, timeout=1)
    results=""
    if SYN_out and not udp and SYN_out['TCP'].flags.value == 18:
        results="TCP Port "+str(port)+" open"
    elif udp and (not SYN_out or (SYN_out and "port-unreachable" not in str(SYN_out.summary()))):
        results="UDP Port "+str(port)+" open"
    else:
        results="Could not access port "+str(port)+"."
    #print(results)
    prot_str="UDP "
    if not udp:
        prot_str="TCP "
    printresults(host,port,udp,prot_str+results,printhtml)

# Allows you to specify a list or a range of ports. "55,56,70-71"
def portscan2(host,ports,udp,icmp,printhtml):
    ports = ports.split(",")
    for port in ports:
        if "-" in port:
            port_more = list(range(int(port[:port.index("-")]),int(port[port.index("-")+1:])+1))
            for port_2 in port_more:
                portscan(host,port_2,udp,printhtml)
        else:
            portscan(host,port,udp,printhtml)
    if icmp:
        prot=ICMP()
        ip = IP(dst=host)
        SYN_out=sr1(ip/prot,timeout=1)
        results=""
        if SYN_out:
            results="open"
        else:
            results="closed"
	printresults(host,"ICMP",None,results,printhtml)


parser = argparse.ArgumentParser(description='Port Scanner')
parser.add_argument('--host', 
                   help='The destination ip')
parser.add_argument('--ports', 
                   help='The destination port(s) to scan. Can also specify multiple ports (eg 2,5,10,11-15)')
parser.add_argument('--udp', default=False, help='Specify --udp if you want to scan udp instead of tcp', action='store_true')
parser.add_argument('--icmp', default=False, action="store_true", help='Specify --icmp if you also want to scan the ip for icmp')
parser.add_argument('--filename', help='Specify --filename followed by the json file listing the ips and ports you want to scan (eg [{"host":"192.168.207.41", "ports": "44,45", "udp": true}]')
parser.add_argument('--html', default=False, action="store_true", help='Specify --html if you want the results printed in html format')

args = parser.parse_args()

# Allows you to either enter the host and port on the command line or to enter a file with valid json format
try:
 if args.filename:
    with open(args.filename, "r") as ins:
        data = ins.read().replace('\n','')
        my_list = json.loads(data)
        for d in my_list:
            portscan2(d['host'],d['ports'],d.get('udp',False),d.get('icmp', False),args.html)

 if args.host and args.ports:
    portscan2(args.host,args.ports,args.udp,args.icmp,args.html)
except IOError:
 print 'Cannot open ', str(args.filename)
except Exception as e:
 print "Error "+str(e)
except:
 print "ERROR: "+str(sys.exc_info()[0])
