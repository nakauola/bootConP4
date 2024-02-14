import socket
import ipaddress

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

if __name__ == "__main__":
    try:
        # Input target IP address
        target_ip = ipaddress.ip_address(input("Enter the target IP address: "))
        # Input start and end ports to scan
        start_port = int(input("Enter the starting port: "))
        end_port = int(input("Enter the ending port: "))
        
        # Scan ports
        open_ports = scan_ports(target_ip, start_port, end_port)
        
        # Print open ports
        if open_ports:
            print("Open ports:")
            for port in open_ports:
                print(port)
        else:
            print("No open ports found.")
    except ValueError:
        print("Invalid IP address or port number.")
