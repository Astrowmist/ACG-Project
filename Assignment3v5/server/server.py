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
import getpass          # Prevents the password from echoing to the terminal when typed
import bcrypt           # For managing passwords
from hashlib import sha256
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding,hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetricPadding
global host, port

cmd_AUTH = "AUTH"
cmd_GET_MENU = "GET_MENU"
cmd_KEY_EXCHANGE = "KEYS"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today"
default_save_base = "result-"

def load_credentials(): # Loads credentials.txt for server computing
    credentials = {}
    with open("credentials.txt", "r") as f:
        for line in f:
            username, hashed = line.strip().split(':')
            credentials[username] = hashed
    return credentials

def authenticate(conn, credentials): # Function for authenticating client username and password
    attempts = 0
    while attempts < 3: # Client must enter correct credentials in 3 attempts
        authentication = False # Initial authentication value set to False

        conn.sendall(b"Username: ") # Prompts for client username
        username = conn.recv(1024).decode().strip() # Receives client username input
        print(f"Received username: {username}")  # Debugging

        if username in credentials:
            authentication = True
    
        else:
            authentication = False

        conn.sendall(b"Password: ") # Prompts for client password
        password = conn.recv(1024).decode().strip() # Receives client password input
        print(f"Received password: {password}")  # Debugging

        try: # Authenticates client password
            if bcrypt.checkpw(password.encode(), credentials[username].encode()):
                authentication = True

            else:
                authentication = False

        except: # Handles client usernames that do not exist
            authentication = False

        if authentication == True: 
            conn.sendall(b"Authentication successful\n")
            return True # authenticate function returns True
        
        else:
            conn.sendall(b"Authentication failed. Try again.\n")
            attempts += 1 # Increment attept by 1 per failed attempt

        if attempts == 3: # Handles final attempt 3 if authentication failed
            conn.sendall(b"Too many failed attempts. Connection closed.\n")
            print("Too many failed attempts. Connection closed.\n")
            conn.close()
            return False # authenticate function returns False
        
def derive_key(password: str):
    # Derive the AES key from the password directly
    return sha256(password.encode()).digest()


def encrypt_file_and_store(data, password , writeFile):
    # Derive the AES key from the password
    key = derive_key(password)

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 16 bytes IV for AES

    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    #Calculate file hash
    dataHash=hashlib.sha512(data).digest()

    # Pad the file data to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to the file

    with open(writeFile, 'wb') as f:
        f.write(iv + encrypted_data + dataHash)

    print(f'Day End Sales data encrypted and saved to {writeFile} with hash')


class IncorrectPasswordError(Exception):
    pass

def decrypt_file(password: str):
    # Derive the AES key from the password
    key = derive_key(password)

    # Read the IV and encrypted data from the file
    try:
        with open(default_menu, 'rb') as f:
            iv = f.read(16)  # Read the first 16 bytes as IV
            encrypted_data_with_hash = f.read()
    except:
        print("file not found : " + default_menu)
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


def load_public_key(file_path: str):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


password = getpass.getpass(prompt='Enter menu Password: ')
try:
    decrypted_menu,data_hash,hashCheck = decrypt_file(password)
except IncorrectPasswordError:
    print('Incorrect Password!')
    sys.exit(0)
except:
    print("***Error: Menu has been altered!***")
    sys.exit(0)

if(data_hash != hashCheck):
    print('\n***Error: Hash does not match !!! The Stored Menu File has been corrupted or altered !!!***\n')
    sys.exit(0)

attempt=0
private_key=load_private_key("./serverKeys/private_key.pem")
public_key=load_public_key("./serverKeys/public_key.pem")
client_public_keyArr = []  # Initialize client_public_key to None
host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server

def process_connection( conn , ip_addr, MAX_BUFFER_SIZE): 
    blk_count = 0
    dayEnd=b''
    hash_object = hashlib.sha512()
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_AUTH in usr_cmd:
                credentials = load_credentials() # Loads credentials from credentials.txt
                if not authenticate(conn, credentials): # Returns value from authenticate function
                    return # Exits function and closes connection as a result
            elif cmd_GET_MENU in usr_cmd: # ask for menu
                try:
                    decrypted_menu,data_hash,hashCheck = decrypt_file(password)
                except:
                    print("***Error: Menu has been altered!***")
                    conn.sendall("\n***Error: Server is going through some momentary difficulties in sending the menu. Please try again later***".encode("utf8"))
                    return
                if(data_hash != hashCheck):
                   print('\n***Error: Hash does not match !!! The Stored Menu File has been corrupted or altered !!!***\n')
                   conn.sendall("\n***Error: Server is going through some momentary difficulties in sending the menu. Please try again later***".encode("utf8"))
                   return
                print("Menu File decrypted and ready to be sent!\n")
                sent_bytes = 0
                while sent_bytes < len(decrypted_menu):
                    chunk = decrypted_menu[sent_bytes:sent_bytes+MAX_BUFFER_SIZE]
                    conn.send(chunk)
                    hash_object.update(chunk)
                    sent_bytes += len(chunk)
                    
                hash_hex = hash_object.hexdigest() # Calculate SHA-512 hash
                conn.send(hash_hex.encode('utf-8')) # Send the hash
                print("Processed SENDING menu and hash") 
                return
            elif cmd_KEY_EXCHANGE in usr_cmd:
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # Send the public key
                conn.sendall(public_key_bytes)
                print("\nServer's public key sent to client")

                received_key_bytes = conn.recv(MAX_BUFFER_SIZE)
                print("\nClient's public key received")
                client_public_keyArr.append(received_key_bytes)
                print("Key Exchange completed")
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)
                dayEnd+=net_bytes[ len(cmd_END_DAY): ]  # remove the CLOSING header    
                blk_count = blk_count + 1
        else:  # write subsequent blocks of END_DAY message block
            # Hints: net_bytes may be an encrypted block of message.
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dayEnd+=net_bytes
    # last block / empty block
    dest_file.close()
    file_data = dayEnd[:-256]  
    signature = dayEnd[-256:]  

    try:
        decrypted_day_end = private_key.decrypt(
            file_data,
            asymmetricPadding.OAEP(
                mgf=asymmetricPadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        print("***Error: Decryption of received Day End Sales failed. Key is incorrect***")
        return
    
    # Verify the signature
    try:
        client_public_key = serialization.load_pem_public_key(
            client_public_keyArr[0],
            backend=default_backend()
        )
        client_public_key.verify(
            signature,
            decrypted_day_end,  # or ciphertext, depending on what was signed
            asymmetricPadding.PSS(
                mgf=asymmetricPadding.MGF1(hashes.SHA256()),
                salt_length=asymmetricPadding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except:
        print("Signature is invalid. File not saved")
        return
    encrypt_file_and_store(decrypted_day_end, password, filename)
    time.sleep(3)
    print("Processed CLOSING done") 
    client_public_keyArr.pop()
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
