# from threading import Thread    # for handling tasks in separate jobs we need threading
# import socket                   # tcp protocol
# import datetime                 # for composing date/time stamp
# import sys                      # handle system error
# import traceback                # for print_exc function
# import time                     # for delay purpose
# from Crypto.Cipher import AES   # for encryption and decryption
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes
# import ssl                      # for SSL/TLS
# import hashlib

# global host, portpy
# cmd_GET_MENU = "GET_MENU"
# cmd_END_DAY = "CLOSING"
# default_menu = "menu_today.txt"
# default_save_base = "result-"

# src_file = open(default_menu, "rb")
      
# read_bytes = src_file.read
# hash_object = hashlib.sha256()
# hash_object.update(read_bytes)
# hash_hex = hash_object.hexdigest()
# print(hash_hex)


# # data = b'byei'  # Data must be in bytes
# # hash_object = hashlib.sha256()
# # hash_object.update(data)
# # hash_hex = hash_object.hexdigest()

# # print(hash_hex)


from threading import Thread    # for handling tasks in separate jobs we need threading
import socket                   # tcp protocol
import datetime                 # for composing date/time stamp
import sys                      # handle system error
import traceback                # for print_exc function
import time                     # for delay purpose
from Crypto.Cipher import AES   # for encryption and decryption
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import ssl                      # for SSL/TLS
import hashlib

global host, portpy
cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"

# Open the file in binary read mode
with open(default_menu, "rb") as src_file:
    read_bytes = src_file.read()

# Create a SHA-256 hash object
hash_object = hashlib.sha256()

# Update the hash object with the bytes read from the file
hash_object.update(read_bytes)

# Get the hexadecimal representation of the hash
hash_hex = hash_object.hexdigest()

# Print the hash
print(hash_hex)
