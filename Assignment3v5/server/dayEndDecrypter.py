import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from hashlib import sha256,sha512

def derive_key(password: str):
    # Derive the AES key from the password directly
    return sha256(password.encode()).digest()



def decrypt_file(encrypted_file_path: str, password: str):
    # Derive the AES key from the password
    key = derive_key(password)

    # Read the IV and encrypted data from the file
    try:
        with open(encrypted_file_path, 'rb') as f:
            iv = f.read(16)  # Read the first 16 bytes as IV
            encrypted_data_with_hash = f.read()
    except:
        print("file not found : " + encrypted_file_path)
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
        print('Incorrect Password!')
        sys.exit(0)
    hashCheck=sha512(decrypted_data).digest()
    if(data_hash != hashCheck):
        print('\nHash does not match !!! The Stored Menu File has been corrupted or altered !!!  \n')
    else:
        decrypted_file_path = "plaintext"
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        print(f'/nFile decrypted and saved to {decrypted_file_path}')


# Example usage
password = input('Password: ')
encrypted_file_path = input('FilePath: ')
decrypt_file(encrypted_file_path, password)

