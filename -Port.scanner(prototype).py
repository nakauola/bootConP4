# bootcon portscanner 

import socket 
import os

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)

print("Your Computer's Name is:" + hostname)
print("Your Computer's IP Address is:" + IPAddr)
print(os.system('ipconfig'))

