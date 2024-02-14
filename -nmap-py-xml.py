import nmap
import xml.etree.ElementTree as ET

def scan_and_parse(target_ip):
    # Create a new instance of the PortScanner class
    nm = nmap.PortScanner()

    # Perform a port scan on the target IP
    nm.scan(hosts=target_ip, arguments='-p 1-1000 -sV')

    # Save the XML output to a file
    xml_output = nm.get_nmap_last_output()
    with open('scan_output.xml', 'w') as f:
        f.write(xml_output)

    # Parse the XML output
    tree = ET.parse('scan_output.xml')
    root = tree.getroot()

    # Extract relevant information from the XML
    for host in root.iter('host'):
        print("Host:", host.find('address').attrib['addr'])
        for port in host.iter('port'):
            print("  Port:", port.attrib['portid'])
            print("    State:", port.find('state').attrib['state'])
            print("    Service:", port.find('service').attrib['name'])
            print("    Product:", port.find('service').attrib.get('product', 'N/A'))
            print("    Version:", port.find('service').attrib.get('version', 'N/A'))
            print("    Extra Info:", port.find('service').attrib.get('extrainfo', 'N/A'))
            print()

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    scan_and_parse(target_ip)
