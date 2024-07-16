# create_credentials.py
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

# Append the new credentials to the file
with open("credentials.txt", "a") as f:
    username = input("Enter username: ")
    password = input("Enter password: ")
    f.write(f"{username}:{hash_password(password)}\n")