import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from hashlib import sha256,sha512

def derive_key(password: str):
    # Derive the AES key from the password directly
    return sha256(password.encode()).digest()

def encrypt_file(file_path: str, password: str):
    # Derive the AES key from the password
    key = derive_key(password)

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 16 bytes IV for AES

    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file content
    with open(file_path, 'rb') as f:
        file_data = f.read()

    dataHash=sha512(file_data).digest()
    #dataHash=sha512("wronghash".encode()).digest()
    # Pad the file data to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to the file
    encrypted_file_path = "day_end"
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data + dataHash)

    print(f'File encrypted and saved to {encrypted_file_path}')

# Example usage
password = input('State the password that you wanna use to encrypt the file: ')
file_path = 'day_end.csv'
encrypt_file(file_path, password)



# def decrypt_file(encrypted_file_path: str, password: str):
#     # Derive the AES key from the password
#     key = derive_key(password)

#     # Read the IV and encrypted data from the file
#     with open(encrypted_file_path, 'rb') as f:
#         iv = f.read(16)  # Read the first 16 bytes as IV
#         encrypted_data = f.read()

#     # Create a cipher object
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()

#     # Decrypt the data
#     decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

#     # Unpad the decrypted data
#     unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#     try:
#         decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
#     except:
#         print('Incorrect Password!')
#         sys.exit(0)

#     decrypted_file_path = "plaintext"
#     with open(decrypted_file_path, 'wb') as f:
#         f.write(decrypted_data)

#     print(decrypted_data)
#     print(f'/nFile decrypted and saved to {decrypted_file_path}')

# # Example usage
# password = input('Password: ')
# encrypted_file_path = 'result-10.10.10.1-2024-07-08_0038'
# decrypt_file(encrypted_file_path, password)

