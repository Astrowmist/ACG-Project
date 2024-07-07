#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
# !/usr/bin/env python3
# Please starts the tcp server first before running this client

import datetime
import sys              # handle system error
import socket
import time
import hashlib          # for hashing
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
global host, port

host = socket.gethostname()
port = 8888         # The port used by the server

cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

# AES block size
BLOCK_SIZE = 16

# Function to encrypt AES key
def rsa_encrypt(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

# Function to encrypt data
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

# Function to decrypt data
def aes_decrypt(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:BLOCK_SIZE]
    ct = enc_data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE)

# Generate AES key
aes_key = get_random_bytes(32)  # AES-256 key length


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))

    # Receive public key from the server
    server_public_key = RSA.import_key(my_socket.recv(1024))
    
    # Encrypt AES key with server's public key
    encrypted_key = rsa_encrypt(aes_key, server_public_key)
    my_socket.sendall(encrypted_key)

    #Command to get menu
    my_socket.sendall(cmd_GET_MENU )
    
    received_data = b''
    while True:
        data = my_socket.recv(4096)
        if not data:
            break
        received_data += data

    file_data = received_data[:-128]  # File data (all except last 128 characters)
    received_hash = received_data[-128:].decode("utf8").rstrip()  # Last 128 characters are the hash

    while True:
        data = my_socket.recv(4096)
        if not data:
            break
        encrypted_menu += data
        
    encrypted_menu = received_data[:-128]  # Remove hash part from encrypted menu data
    menu_data = aes_decrypt(encrypted_menu.decode('utf-8'), aes_key)

    hash_object = hashlib.sha512()
    hash_object.update(file_data)
    hash_hex = hash_object.hexdigest()

    if(hash_hex != received_hash):
        print('\nHash does not match !!! Menu has been corrupted or altered !!! Ending connection... \n')
        my_socket.close()
        sys.exit(0)
    menu_file = open(menu_file,"wb")
    menu_file.write(file_data)
    menu_file.close()
    my_socket.close()
print('Menu today received from server')
#print('Received', repr(data))  # for debugging use
my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
        out_file = open(return_file,"rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    file_bytes = out_file.read(1024)
    sent_bytes=b''
    while file_bytes != b'':
        # hints: need to protect the file_bytes in a way before sending out.
        my_socket.send(file_bytes)
        sent_bytes+=file_bytes
        file_bytes = out_file.read(1024) # read next block from file
    out_file.close()
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()


# brandon test code
#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please start the tcp server first before running this client

# import sys
# import socket
# import hashlib
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad

# global host, port

# host = socket.gethostname()
# port = 8888
# cmd_GET_MENU = b"GET_MENU"
# cmd_END_DAY = b"CLOSING"
# menu_file = "menu.csv"
# return_file = "day_end.csv"

# # AES configuration
# AES_KEY = b'1234567890123456'
# AES_IV = b'1234567890123456'

# def encrypt_data(data, key, iv):
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     encrypted_data = cipher.encrypt(pad(data, AES.block_size))
#     return encrypted_data

# def decrypt_data(data, key, iv):
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
#     return decrypted_data

# def hash_data(data):
#     return hashlib.sha512(data).hexdigest()

# # Step 1: Receive and decrypt the menu
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     my_socket.connect((host, port))
#     my_socket.sendall(cmd_GET_MENU)
#     received_data = b''
#     while True:
#         data = my_socket.recv(4096)
#         if not data:
#             break
#         received_data += data

#     # Separate the encrypted data and the hash
#     encrypted_data = received_data[:-128]
#     received_hash = received_data[-128:].decode("utf-8").rstrip()

#     # Decrypt the received data
#     try:
#         decrypted_data = decrypt_data(encrypted_data, AES_KEY, AES_IV)
#     except Exception as e:
#         print(f"Decryption error: {e}")
#         sys.exit(0)

#     # Verify the hash
#     calculated_hash = hash_data(decrypted_data)
#     if calculated_hash != received_hash:
#         print('\nHash does not match! Menu has been corrupted or altered. Ending connection...\n')
#         my_socket.close()
#         sys.exit(0)

#     # Write the decrypted data to the menu file
#     with open(menu_file, "wb") as menu_file_obj:
#         menu_file_obj.write(decrypted_data)

#     print('Menu today received from server and verified.')
#     my_socket.close()

# # Step 2: Encrypt and send the end-of-day sales report
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     my_socket.connect((host, port))
#     my_socket.sendall(cmd_END_DAY)
#     try:
#         with open(return_file, "rb") as out_file:
#             while True:
#                 file_bytes = out_file.read(1024)
#                 if not file_bytes:
#                     break
#                 encrypted_bytes = encrypt_data(file_bytes, AES_KEY, AES_IV)
#                 my_socket.sendall(encrypted_bytes)
#     except FileNotFoundError:
#         print("file not found: " + return_file)
#         sys.exit(0)
#     my_socket.close()
# print('Sale of the day sent to server')


 
# Rowhith Commit

# import datetime
# import sys              # handle system error
# import socket
# import time
# import hashlib          # for hashing
# global host, port

# host = socket.gethostname()
# port = 8888         # The port used by the server
# cmd_GET_MENU = b"GET_MENU"
# cmd_END_DAY = b"CLOSING"
# menu_file = "menu.csv"
# return_file = "day_end.csv"


# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     my_socket.connect((host, port))
#     my_socket.sendall(cmd_GET_MENU )
#     received_data = b''
#     while True:
#         data = my_socket.recv(4096)
#         if not data:
#             break
#         received_data += data
#     file_data = received_data[:-128]  # File data (all except last 128 characters)
#     received_hash = received_data[-128:].decode("utf8").rstrip()  # Last 128 characters are the hash
#     hash_object = hashlib.sha512()
#     hash_object.update(file_data)
#     hash_hex = hash_object.hexdigest()
#     if(hash_hex != received_hash):
#         print('\nHash does not match !!! Menu has been corrupted or altered !!! Ending connection... \n')
#         my_socket.close()
#         sys.exit(0)
#     menu_file = open(menu_file,"wb")
#     menu_file.write(file_data)
#     menu_file.close()
#     my_socket.close()
# print('Menu today received from server')
# #print('Received', repr(data))  # for debugging use
# my_socket.close()

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     my_socket.connect((host, port))
#     my_socket.sendall(cmd_END_DAY)
#     try:
#         out_file = open(return_file,"rb")
#     except:
#         print("file not found : " + return_file)
#         sys.exit(0)
#     file_bytes = out_file.read(1024)
#     sent_bytes=b''
#     while file_bytes != b'':
#         # hints: need to protect the file_bytes in a way before sending out.
#         my_socket.send(file_bytes)
#         sent_bytes+=file_bytes
#         file_bytes = out_file.read(1024) # read next block from file
#     out_file.close()
#     my_socket.close()
# print('Sale of the day sent to server')
# #print('Sent', repr(sent_bytes))  # for debugging use
# my_socket.close()



































# #------------------------------------------------------------------------------------------
# # Client.py UPDATED
# #------------------------------------------------------------------------------------------
# #!/usr/bin/env python3
# # Please start the TCP server first before running this client

# import sys              # handle system error
# import socket
# import ssl              # for SSL/TLS
# from Crypto.Cipher import AES  # for encryption and decryption
# from Crypto.Util.Padding import pad, unpad

# # Constants
# global host, port
# cmd_GET_MENU = b"GET_MENU"
# cmd_END_DAY = b"CLOSING"
# menu_file = "menu.csv"
# return_file = "day_end.csv"
# secret_key = b'Sixteen byte key'  # This should be stored securely

# host = socket.gethostname()
# port = 8888  # The port used by the server

# # Encryption and Decryption functions
# def encrypt_data(data, key):
#     cipher = AES.new(key, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(data, AES.block_size))
#     iv = cipher.iv
#     return iv + ct_bytes

# def decrypt_data(encrypted_data, key):
#     iv = encrypted_data[:AES.block_size]
#     ct = encrypted_data[AES.block_size:]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     pt = unpad(cipher.decrypt(ct), AES.block_size)
#     return pt

# # SSL/TLS context for secure communication
# context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
# context.load_verify_locations("server.crt")

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     conn = context.wrap_socket(my_socket, server_hostname=host)
#     conn.connect((host, port))
#     conn.sendall(cmd_GET_MENU)
#     encrypted_data = conn.recv(4096)
#     # Decrypt received data
#     data = decrypt_data(encrypted_data, secret_key)
#     menu_file = open(menu_file, "wb")
#     menu_file.write(data)
#     menu_file.close()
#     conn.close()
# print('Menu today received from server')

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
#     conn = context.wrap_socket(my_socket, server_hostname=host)
#     conn.connect((host, port))
#     conn.sendall(cmd_END_DAY)
#     try:
#         out_file = open(return_file, "rb")
#     except:
#         print("file not found : " + return_file)
#         sys.exit(0)
#     file_bytes = out_file.read(1024)
#     while file_bytes != b'':
#         # Encrypt data before sending
#         encrypted_bytes = encrypt_data(file_bytes, secret_key)
#         conn.send(encrypted_bytes)
#         file_bytes = out_file.read(1024)  # read next block from file
#     out_file.close()
#     conn.close()
# print('Sale of the day sent to server')
