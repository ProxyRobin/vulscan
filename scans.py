#!/usr/bin/python
import sys
import nmap
import shodan

SHODAN_API_KEY = "Ld4jdENSFPTWdboKv2wodf82RWjtPNLs"

shdn = shodan.Shodan(SHODAN_API_KEY)
nm = nmap.PortScanner()

def main(op = None):
    home = '127.0.0.1'
    away = "208.75.151.140"
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

def nmapIP(ip):
    print "#"*15, "\n nmap \n", "#"*15
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
    for cell in nmcsv.split(';')[:-1]:
        nms += cell + " | "
    #    nms += '\n'
    print nms


def shodanIP(ip):
    print "#"*15, "\n Shodan \n", "#"*15
    host = shdn.host(ip)
    print """
    IP: %s
    Organization: %s
    Operating System: %s
    """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))

    for item in host['data']:
        print """
        Port: %s
        Banner: %s
        """ % (item['port'], item['data'])

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main()
    else:
        main(sys.argv[1])
