import nmap


#bootcon portscanner 

#nmps Nmap Portscanner for vulnerability reporting - Dillon M 1/28/24
#nmap scanner framework from https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap

nmps = nmap.PortScanner()

target = "127.0.0.1"
options = "-sV -Os scan_results"

nmps.scan(target, arguments=options)

for host in nmps.all_hosts():
    print("Host: %s (%s)" & (host, nmps[host].hostname()))
    print("State: %s" % nmps[host].state())
    for protocol in nmps[host].all_protocols():
        print("Protocol: %s" % protocol)
        port_info = nmps[host][protocol]
        for port, state in port_info.items():
            print("Port: %s\tState: %s" % (port, state))

#nmps.scan('127.0.0.1', '22-443')
#nmps.command_line()
#' -oX - -p 22-443 -sV 127.0.0.1'
#nmps.scaninfo()
#{'tcp': {'services': '22-443', 'method': 'connect'}}
#nmps.scan.all_hosts()
#['127.0.0.1']
#nmps['127.0.0.1'].state()
#'up'
#nmps['127.0.0.1'].all_protocols()
#['tcp']
#nmps['127.0.0.1']['tcp'].keys()
#[80, 25, 443, 22, 111]
#nmps['127.0.0.1'].has_tcp(22)
#True
#nmps['127.0.0.1'].has_tcp(23)
#False
#nmps['127.0.0.1']['tcp'][22]
#{'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
#nmps['127.0.0.1'].tcp(22)
#{'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
