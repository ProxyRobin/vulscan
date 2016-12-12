#!/usr/bin/python
import sys
import nmap
import shodan
from datetime import datetime

SHODAN_API_KEY = "Ld4jdENSFPTWdboKv2wodf82RWjtPNLs"

shdn = shodan.Shodan(SHODAN_API_KEY)
nm = nmap.PortScanner()

def main(op = None):
    home = '127.0.0.1'
    away = '208.75.151.140'
    if op == "nmap":
        nmapIP(away)
    elif op == "hnmap":
        nmapIP(home)
    elif op == "shodan":
        shodanIP(away)
    elif op == "both":
        nmapIP(away)
        shodanIP(away)
    else:
        print "Input an operation: nmap, hnmap, shodan, both"

def report(ip):
    nm.scan(ip)
    time = datetime.now()
    report = """
***************
VULSCAN REPORT
COMPILED AT %s
***************
IP: %s (%s)
----
Open Ports: %s
----
Filtered Ports: %s

""" %(time, ip, nm[ip].hostname(), )


def nmapIP(ip):
    print "#"*15, "\n nmap by IP\n", "#"*15
    nms = ""
    nm.scan(ip)
    nms += '--------\n Host: %s (%s) \n'%(ip,nm[ip].hostname())
    for proto in nm[ip].all_protocols():
        nms += '--------\n'
        nms += 'Protocol: %s \n' % proto
        lport = nm[ip][proto].keys()
        lport.sort()
        print
        for port in lport:
            nms += "Port: %s\tstate: %s \n" %(port, nm[ip][proto][port]['state'])
    nms += '--------\n'
    nmcsv = nm.csv()
    nms += nmcsv + '-'*8 + '\n'
    #for col in nmcsv.split('\n'):
    for cell in nmcsv.split(';'):
        nms += cell + " | "
    #    nms += '\n'
    print nms

def nmapPortInfo(ip,proto,ports):
    info = ""
    nm.scan(ip)
    for port in ports:
        info += str(port) + " | "
        info += nm[ip][proto][port]['name'] + " | "
        info += nm[ip][proto][port]['product'] + " | "
        info += nm[ip][proto][port]['version'] + "\n"
    print info

def shodanToNmap(ip):
    nmapPorts(ip, " ".join((str(e) + ",") for e in shodanIP(ip)))

#Scans specified ports for given IP.
def nmapPorts(ip, ports):
    print "#"*15, "\n nmap by ports\n", "#"*15
    nm.scan(ip, ports)
    nms = ""
    for cell in nm.csv().split(';'):
        nms += cell + " | "
    print nms

# Prints a standard Shodan report. Returns ports found.
def shodanIP(ip):
    print "#"*15, "\n Shodan \n", "#"*15
    host = shdn.host(ip)
    portset = set()
    print """
IP: %s
Organization: %s
Operating System: %s
""" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))

    for item in host['data']:
        portset.add(item['port'])
        print """
--------

Port: %s
Banner: %s
""" % (item['port'], item['data'])
    return list(portset)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main()
    else:
        main(sys.argv[1])
