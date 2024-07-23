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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding,hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetricPadding
global host, port

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_AUTH = b"AUTH"
cmd_GET_MENU = b"GET_MENU"
cmd_KEY_EXCHANGE = b"KEYS"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end"

# Function for authentication
# Done by XAVION
def authenticate(my_socket):

    response = my_socket.recv(1024).decode() # Receive initial response from server (username input)

    while "Authentication successful" not in response: # Checks for authentication status

        if "successful" in response:
            print("Authentication successful.")
        
        if "closed" in response:
            print("Too many failed attempts. Connection closed.\n")
            sys.exit()

        username = input(f'{response}')
        while username == '': # Checks for empty string value
            print('Username cannot be empty.')
            username = input(f'{response}')
        my_socket.sendall(username.encode()) # Sends username of client to server

        response = my_socket.recv(1024).decode() # Receives response from server (password input)

        password = getpass.getpass(response)
        while password == '': # Checks for empty string value
            print('Password cannot be empty.')
            password = getpass.getpass(response)
        my_socket.sendall(password.encode()) # Sends password of client to server

        response = my_socket.recv(1024).decode() # Receives authentication status from server

        if "Authentication failed" in response:
            print(response)
            response = my_socket.recv(1024).decode()

    print("Authentication successful.")

# Done by BRANDON
def derive_key(password: str):
    # Derive the AES key from the password directly
    return sha256(password.encode()).digest()


class IncorrectPasswordError(Exception):
    pass
# Done by BRANDON
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
        sys.exit(1)

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

# Done by ROWHITH
def load_private_key(file_path: str):
    global attempt  # Declare that we're using the global attempt variable
    while attempt < 3:
        try:
            password = getpass.getpass(prompt="Enter the password to decrypt the private key: ").encode()
            with open(file_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password,
                    backend=default_backend()
                )
            print("Private key successfully loaded.")
            return private_key
        except ValueError:
            print("Incorrect password. Please try again.")
            attempt += 1
    print("Too many incorrect attempts. Exiting.")
    sys.exit(1)

# Done by ROWHITH
def load_public_key(file_path: str):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# Done by XAVION
# Socket for Authentication
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket: # Socket for authentication
    my_socket.connect((host, port))
    my_socket.sendall(cmd_AUTH)
    authenticate(my_socket)

    my_socket.close()

for _ in (True,):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
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
# Done by YU JIE
    file_data = received_data[:-128]  # File data (all except last 128 characters)
    received_hash = received_data[-128:].decode("utf8").rstrip()  # Last 128 characters are the hash
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

password = getpass.getpass(prompt='Enter day_end Password: ')
# Done by BRANDON
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
attempt =0
private_key=load_private_key("./clientKeys/private_key.pem")
public_key=load_public_key("./clientKeys/public_key.pem")

# Key Exchange Done by ROWHITH
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_KEY_EXCHANGE)
    received_key_bytes = my_socket.recv(4096)
    server_public_key = serialization.load_pem_public_key(
        received_key_bytes,
        backend=default_backend()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Send the public key
    my_socket.sendall(public_key_bytes)
    print('sent key')
    my_socket.close()
print('Keys Successfully exchanged')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
# Done by ROWHITH
    encrypted_data = server_public_key.encrypt(
        decrypted_day_end,
        asymmetricPadding.OAEP(
            mgf=asymmetricPadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    signature = private_key.sign(
        decrypted_day_end,
        asymmetricPadding.PSS(
            mgf=asymmetricPadding.MGF1(hashes.SHA256()),
            salt_length=asymmetricPadding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    sent_bytes = 0
    while sent_bytes < len(encrypted_data):
        chunk = encrypted_data[sent_bytes:sent_bytes+1024]
        my_socket.send(chunk)
        sent_bytes += len(chunk)
    my_socket.sendall(signature)
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()

