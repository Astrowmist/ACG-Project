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
import getpass          # Prevents the password from echoing to the terminal when typed
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
global host, port

host = socket.gethostname()
port = 8888         # The port used by the server

cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end"

def derive_key(password: str):
    # Derive the AES key from the password directly
    return sha256(password.encode()).digest()


class IncorrectPasswordError(Exception):
    pass

def decrypt_file(password: str):
    # Derive the AES key from the password
    key = derive_key(password)

    # Read the IV and encrypted data from the file
    try:
        with open(return_file, 'rb') as f:
            iv = f.read(16)  # Read the first 16 bytes as IV
            encrypted_data_with_hash = f.read()
    except:
        print("file not found : " + return_file)
        sys.exit(0)

    # Separate the encrypted data and the hash
    encrypted_data = encrypted_data_with_hash[:-64]
    data_hash = encrypted_data_with_hash[-64:]


    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except:
        raise IncorrectPasswordError()

    hashCheck=hashlib.sha512(decrypted_data).digest()
    return decrypted_data,data_hash,hashCheck

password = getpass.getpass(prompt='Enter day_end Password: ')

for _ in (True,):
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

    if 'Error' in received_data.decode("utf8").rstrip():
        print(received_data.decode("utf8").rstrip())
        my_socket.close()
        break

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
        print('\n***Error: Hash does not match! Menu has been corrupted or altered! Ending connection...***\n')
        my_socket.close()
        break
    menu_file = open(menu_file,"wb")
    menu_file.write(file_data)
    menu_file.close()
    my_socket.close()
    print('Menu today received from server')
#print('Received', repr(data))  # for debugging use
my_socket.close()

try:
    decrypted_day_end,data_hash,hashCheck = decrypt_file(password)
except IncorrectPasswordError:
    print('Incorrect Password!')
    sys.exit(1)
except:
    print("***Error: day_end File has been altered! File has not been sent.***")
    sys.exit(1)

if(data_hash != hashCheck):
    print('\n***Error: Hash does not match! The Stored Day End Sales File has been corrupted or altered! day_end File has not been sent.***\n')
    sys.exit(0)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)

    sent_bytes = 0
    while sent_bytes < len(decrypted_day_end):
        chunk = decrypted_day_end[sent_bytes:sent_bytes+1024]
        my_socket.send(chunk)
        sent_bytes += len(chunk)
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
