from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import getpass

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Generate the corresponding public key
public_key = private_key.public_key()

# Prompt the user for a password to encrypt the private key
password = getpass.getpass(prompt="Enter a password to encrypt the private key: ").encode()

# Save the private key to a PEM file with encryption
with open("./private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    ))

# Save the public key to a PEM file
with open("./public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print("Private and public keys have been generated and saved.")
