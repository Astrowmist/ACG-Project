# ------------------------------------------------------------------------------------------
# Server.py
# ------------------------------------------------------------------------------------------

from threading import Thread    # for handling task in separate jobs we need threading
import socket           # tcp protocol
import datetime         # for composing date/time stamp
import sys              # handle system error
import traceback        # for print_exc function
import time             # for delay purpose
import hashlib          # for hashing
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes
import base64
global host, port

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"
hash="hash.txt"

host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server

# RSA Key Generation
private_key = RSA.generate(2048)
public_key = private_key.publickey()


# AES block size
BLOCK_SIZE = 16

# Function to decrypt AES key
def rsa_decrypt(encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

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


def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):  
    blk_count = 0
    hash_object = hashlib.sha512()
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd: # ask for menu
                try:
                    src_file = open(default_menu,"rb")
                except:
                    print("file not found : " + default_menu)
                    sys.exit(0)
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    hash_object.update(read_bytes) # Add the file bytes to hash object

                    # Encrypt the menu data
                    encrypted_menu = aes_encrypt(default_menu, private_key).encode('utf-8')
                                    
                    if read_bytes == b'':
                        break
                    conn.send(read_bytes)
                src_file.close()
                hash_hex = hash_object.hexdigest() # Calculate SHA-256 hash
                # conn.send(encrypted_menu)
                conn.send(hash_hex.encode('utf-8')) # Send the hash
                print("Processed SENDING menu and hash") 
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

                # Decrypt received data
                # decrypted_data = aes_decrypt(net_bytes[len(cmd_END_DAY):].decode('utf-8'), sales_key)

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)
                dest_file.write( net_bytes[ len(cmd_END_DAY): ] ) # remove the CLOSING header    
                blk_count = blk_count + 1
        else:  # write subsequent blocks of END_DAY message block
            # Hints: net_bytes may be an encrypted block of message.
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    dest_file.close()
    print("saving file as " + filename)
    time.sleep(3)
    print("Processed CLOSING done") 
    return

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + "ended")
    return

def start_server():
    global host, port
    # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')
    
    try:
        soc.bind((host, port))
        print('Socket bind complete')
    except socket.error as msg:
        
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket and can accept 10 connection
    soc.listen(10)
    print('Socket now listening')

    # this will make an infinite loop needed for 
    # not reseting server for every client
    try:
        while True:
            conn, addr = soc.accept()
            # assign ip and port
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port)
            try:
                Thread(target=client_thread, args=(conn, ip, port)).start()
            except:
                print("Terrible error!")
                traceback.print_exc()
    except:
        pass
    soc.close()
    return

start_server()  











# brandon test code
# from threading import Thread
# import socket
# import datetime
# import sys
# import traceback
# import hashlib
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad

# global host, port

# cmd_GET_MENU = "GET_MENU"
# cmd_END_DAY = "CLOSING"
# default_menu = "menu_today.txt"
# default_save_base = "result-"
# hash_file = "hash.txt"

# host = socket.gethostname()
# port = 8888

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

# def process_connection(conn, ip_addr, MAX_BUFFER_SIZE):
#     blk_count = 0
#     net_bytes = conn.recv(MAX_BUFFER_SIZE)
#     dest_file = open("temp", "w")
#     while net_bytes != b'':
#         if blk_count == 0:
#             usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
#             if cmd_GET_MENU in usr_cmd:
#                 try:
#                     with open(default_menu, "rb") as src_file:
#                         menu_data = b''
#                         while True:
#                             read_bytes = src_file.read(MAX_BUFFER_SIZE)
#                             if read_bytes == b'':
#                                 break
#                             menu_data += read_bytes

#                         # Encrypt the menu data
#                         encrypted_menu = encrypt_data(menu_data, AES_KEY, AES_IV)

#                         # Calculate hash of the original menu data
#                         hash_hex = hash_data(menu_data)

#                         # Send encrypted data followed by hash
#                         conn.sendall(encrypted_menu + hash_hex.encode('utf-8'))
#                         print("Processed SENDING menu and hash")
#                         return
#                 except FileNotFoundError:
#                     print(f"File not found: {default_menu}")
#                     conn.close()
#                     return
#                 except Exception as e:
#                     print(f"Error reading file: {e}")
#                     traceback.print_exc()
#                     conn.close()
#                     return
#             elif cmd_END_DAY in usr_cmd:
#                 now = datetime.datetime.now()
#                 filename = default_save_base + ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
#                 dest_file = open(filename, "wb")

#                 # Write the first block without the header
#                 dest_file.write(net_bytes[len(cmd_END_DAY):])
#                 blk_count += 1
#         else:
#             net_bytes = conn.recv(MAX_BUFFER_SIZE)
#             if not net_bytes:
#                 break
#             dest_file.write(net_bytes)

#     dest_file.close()
#     print("saving file as " + filename)
#     time.sleep(3)
#     print("Processed CLOSING done")
#     return

# def client_thread(conn, ip, port, MAX_BUFFER_SIZE=4096):
#     process_connection(conn, ip, MAX_BUFFER_SIZE)
#     conn.close()
#     print('Connection ' + ip + ':' + port + " ended")
#     return

# def start_server():
#     global host, port
#     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     print('Socket created')

#     try:
#         soc.bind((host, port))
#         print('Socket bind complete')
#     except socket.error as msg:
#         print('Bind failed. Error : ' + str(sys.exc_info()))
#         print(msg.with_traceback())
#         sys.exit()

#     soc.listen(10)
#     print('Socket now listening')

#     try:
#         while True:
#             conn, addr = soc.accept()
#             ip, port = str(addr[0]), str(addr[1])
#             print('Accepting connection from ' + ip + ':' + port)
#             try:
#                 Thread(target=client_thread, args=(conn, ip, port)).start()
#             except:
#                 print("Terrible error!")
#                 traceback.print_exc()
#     except:
#         pass
#     soc.close()
#     return

# start_server()














# from threading import Thread    # for handling task in separate jobs we need threading
# import socket           # tcp protocol
# import datetime         # for composing date/time stamp
# import sys              # handle system error
# import traceback        # for print_exc function
# import time             # for delay purpose
# import hashlib          # for hashing
# global host, port

# cmd_GET_MENU = "GET_MENU"
# cmd_END_DAY = "CLOSING"
# default_menu = "menu_today.txt"
# default_save_base = "result-"
# hash="hash.txt"

# host = socket.gethostname() # get the hostname or ip address
# port = 8888                 # The port used by the server

# def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):  
#     blk_count = 0
#     hash_object = hashlib.sha512()
#     net_bytes = conn.recv(MAX_BUFFER_SIZE)
#     dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
#     while net_bytes != b'':
#         if blk_count == 0: #  1st block
#             usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
#             if cmd_GET_MENU in usr_cmd: # ask for menu
#                 try:
#                     src_file = open(default_menu,"rb")
#                 except:
#                     print("file not found : " + default_menu)
#                     sys.exit(0)
#                 while True:
#                     read_bytes = src_file.read(MAX_BUFFER_SIZE)
#                     hash_object.update(read_bytes) # Add the file bytes to hash object
                                    
#                     if read_bytes == b'':
#                         break
#                     conn.send(read_bytes)
#                 src_file.close()
#                 hash_hex = hash_object.hexdigest() # Calculate SHA-256 hash
#                 conn.send(hash_hex.encode('utf-8')) # Send the hash
#                 print("Processed SENDING menu and hash") 
#                 return
#             elif cmd_END_DAY in usr_cmd: # ask for to save end day order
#                 #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
#                 now = datetime.datetime.now()
#                 filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
#                 dest_file = open(filename,"wb")

#                 # Hints: net_bytes may be an encrypted block of message.
#                 # e.g. plain_bytes = my_decrypt(net_bytes)
#                 dest_file.write( net_bytes[ len(cmd_END_DAY): ] ) # remove the CLOSING header    
#                 blk_count = blk_count + 1
#         else:  # write subsequent blocks of END_DAY message block
#             # Hints: net_bytes may be an encrypted block of message.
#             net_bytes = conn.recv(MAX_BUFFER_SIZE)
#             dest_file.write(net_bytes)
#     # last block / empty block
#     dest_file.close()
#     print("saving file as " + filename)
#     time.sleep(3)
#     print("Processed CLOSING done") 
#     return

# def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
#     process_connection( conn, ip, MAX_BUFFER_SIZE)
#     conn.close()  # close connection
#     print('Connection ' + ip + ':' + port + "ended")
#     return

# def start_server():
#     global host, port
#     # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
#     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # this is for easy starting/killing the app
#     soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     print('Socket created')
    
#     try:
#         soc.bind((host, port))
#         print('Socket bind complete')
#     except socket.error as msg:
        
#         print('Bind failed. Error : ' + str(sys.exc_info()))
#         print( msg.with_traceback() )
#         sys.exit()

#     #Start listening on socket and can accept 10 connection
#     soc.listen(10)
#     print('Socket now listening')

#     # this will make an infinite loop needed for 
#     # not reseting server for every client
#     try:
#         while True:
#             conn, addr = soc.accept()
#             # assign ip and port
#             ip, port = str(addr[0]), str(addr[1])
#             print('Accepting connection from ' + ip + ':' + port)
#             try:
#                 Thread(target=client_thread, args=(conn, ip, port)).start()
#             except:
#                 print("Terrible error!")
#                 traceback.print_exc()
#     except:
#         pass
#     soc.close()
#     return

# start_server()  






































# #------------------------------------------------------------------------------------------
# # Server.py UPDATED
# #------------------------------------------------------------------------------------------
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

# # Constants
# global host, portpy
# cmd_GET_MENU = "GET_MENU"
# cmd_END_DAY = "CLOSING"
# default_menu = "menu_today.txt"
# default_save_base = "result-"
# secret_key = b'Sixteen byte key' # This should be stored securely

# host = socket.gethostname() # get the hostname or ip address
# port = 8888                 # The port used by the server

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

# def process_connection(conn, ip_addr, MAX_BUFFER_SIZE):
#     blk_count = 0
#     net_bytes = conn.recv(MAX_BUFFER_SIZE)
#     dest_file = open("temp", "wb")  # temp file is to satisfy the syntax rule. Can ignore the file.
#     while net_bytes != b'':
#         if blk_count == 0:  # 1st block
#             usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
#             if cmd_GET_MENU in usr_cmd:  # ask for menu
#                 try:
#                     src_file = open(default_menu, "rb")
#                 except:
#                     print("file not found : " + default_menu)
#                     sys.exit(0)
#                 while True:
#                     read_bytes = src_file.read(MAX_BUFFER_SIZE)
#                     if read_bytes == b'':
#                         break
#                     # Encrypt data before sending
#                     encrypted_data = encrypt_data(read_bytes, secret_key)
#                     conn.send(encrypted_data)
#                 src_file.close()
#                 print("Processed SENDING menu")
#                 return
#             elif cmd_END_DAY in usr_cmd:  # ask to save end day order
#                 now = datetime.datetime.now()
#                 filename = default_save_base + ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
#                 dest_file = open(filename, "wb")

#                 # Decrypt data after receiving
#                 decrypted_data = decrypt_data(net_bytes[len(cmd_END_DAY):], secret_key)
#                 dest_file.write(decrypted_data)
#                 blk_count = blk_count + 1
#         else:  # write subsequent blocks of END_DAY message block
#             net_bytes = conn.recv(MAX_BUFFER_SIZE)
#             decrypted_data = decrypt_data(net_bytes, secret_key)
#             dest_file.write(decrypted_data)
#     # last block / empty block
#     dest_file.close()
#     print("saving file as " + filename)
#     time.sleep(3)
#     print("Processed CLOSING done")
#     return

# def client_thread(conn, ip, port, MAX_BUFFER_SIZE=4096):
#     process_connection(conn, ip, MAX_BUFFER_SIZE)
#     conn.close()  # close connection
#     print('Connection ' + ip + ':' + port + " ended")
#     return

# def start_server():
#     global host, port
#     # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM.
#     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # this is for easy starting/killing the app
#     soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     print('Socket created')

#     try:
#         soc.bind((host, port))
#         print('Socket bind complete')
#     except socket.error as msg:
#         print('Bind failed. Error : ' + str(sys.exc_info()))
#         print(msg.with_traceback())
#         sys.exit()

#     # Start listening on socket and can accept 10 connection
#     soc.listen(10)
#     print('Socket now listening')

#     # Wrap socket with SSL/TLS
#     context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#     context.load_cert_chain(certfile="server.crt", keyfile="server.key")
#     soc = context.wrap_socket(soc, server_side=True)

#     try:
#         while True:
#             conn, addr = soc.accept()
#             # assign ip and port
#             ip, port = str(addr[0]), str(addr[1])
#             print('Accepting connection from ' + ip + ':' + port)
#             try:
#                 Thread(target=client_thread, args=(conn, ip, port)).start()
#             except:
#                 print("Terrible error!")
#                 traceback.print_exc()
#     except:
#         pass
#     soc.close()
#     return

# start_server()
