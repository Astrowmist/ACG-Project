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
global host, port

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"
hash="hash.txt"

host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server

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
                                    
                    if read_bytes == b'':
                        break
                    conn.send(read_bytes)
                src_file.close()
                hash_hex = hash_object.hexdigest() # Calculate SHA-256 hash
                conn.send(hash_hex.encode('utf-8')) # Send the hash
                print("Processed SENDING menu and hash") 
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

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
