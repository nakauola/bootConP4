import socket
import ipaddress
import nmap
import subprocess
import shlex

def scan_ports(target_ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set timeout to 1 second
            s.settimeout(1)
            # Attempt to connect to the target IP and port
            result = s.connect_ex((str(target_ip), port))
            # If the connection was successful, the port is open
            if result == 0:
                open_ports.append(port)
            # Close the socket
            s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports 

#nmap import to run parallel
def scan_ports_nmap(target_ip, start_port, end_port):
    open_ports = []
    try: 
        nm = nmap.PortScanner
        nm.scan(hosts=str(target_ip), arguments=f"-p {start_port}-{end_port} -sS")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport =  nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
    except Exception as e:
        print(f"Error scanning ports: {e}")
    return open_ports #end of nmap import script

def get_service_name(port):
    try:
        # Get the service name associated with the port
        service_name = socket.getservbyport(port)
        return service_name
    except OSError:
        # Handle the case where the service name is not found for the port
        return "Unknown"

def netstat_scan():
    try:
        # Sanitize command to prevent shell injection
        command = ["netstat", "-tuln"]
        sanitized_command = [shlex.quote(arg) for arg in command]
    #execute netstat command and capture output 
        netstat_output = subprocess.check_output(sanitized_command)
        netstat_output = netstat_output.decode("utf-8") # Convert byte
        lines = netstat_output.split("\n")
        print("Proto    Local Address         Foreign Address           State")
        for line in lines:
            print(line)
    except Exception as e:
        print(f"Error executing netstat command: {e}")
        return None
    # Call the netstat_scan function to perform the scan
    netstat_output = netstat_scan()
    if netstat_output:
        print("Netstat Output:")
        print(netstat_output)

if __name__ == "__main__":
    try:
        # Input target IP address
        target_ip = ipaddress.ip_address(input("Enter the target IP address: "))
        # Input start and end ports to scan
        start_port = int(input("Enter the starting port: "))
        end_port = int(input("Enter the ending port: "))
        print("Starting scan, go get yourself a coffee")
        # Scan ports
        open_ports = scan_ports(target_ip, start_port, end_port)
        # Print open ports and their associated services
        if open_ports:
            print("Open ports:")
            for port in open_ports:
                service_name = get_service_name(port)
                print(f"Port: {port}, Service: {service_name}")
        else:
            print("No open ports found.")
    except ValueError:
        print("Invalid IP address or port number.")
