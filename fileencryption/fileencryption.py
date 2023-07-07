from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import base64
import getpass
import bcrypt
import logging

def getPassword():
    with open("password.hash", "rb") as pwdFile:
        return pwdFile.read()

def setPassword():
    senha1 = getpass.getpass("\nType your new password: ")
    senha2 = getpass.getpass("Confirm your new password: ")

    while senha1 != senha2:
        logging.warning("THE PASSWORDS DON'T MATCH\n")
        senha1 = getpass.getpass("Type your new password: ")
        senha2 = getpass.getpass("Confirm your new password: ")

    if (int(input("Generate new salt? (0 - No | 1 - Yes) ")) > 0):
        workFactor = int(input("Salt size (0 to use the standard size 12): "))
        salt = generateSalt((workFactor if workFactor > 0 else 12))
        with open("salt.salt", "wb") as saltFile:
            saltFile.write(salt)
    else:
        salt = loadSalt()
        workFactor = int(salt.decode().split("$")[2])

    logging.info(f"Generating new Bcrypt hash with Work Factor of {workFactor}\n")
    with open("password.hash", "wb") as pwdFile:
        pwdFile.write(bcrypt.hashpw(senha1.encode(), salt))

    logging.info("New password set successfully\n")

def resetPassword():
    try:
        password_hash = getPassword()

        password_old = getpass.getpass("\nType your old password: ")

        if checkPassword(password_old, password_hash):
            print("****** Reset password ******")
            setPassword()
        else:
            logging.error("PASSWORDS DON'T MATCH")
        
    except FileNotFoundError:
        setPassword()

def checkPassword(password_input, password_old_hash=""):
    logging.info(f"Checking Password\n")
    password_hash = getPassword() if password_old_hash == "" else password_old_hash
    return bcrypt.checkpw(password_input.encode(), password_hash)

def generateSalt(work_factor):
    return bcrypt.gensalt(rounds=work_factor)

def loadSalt():
    with open("salt.salt", "rb") as saltFile:
        return saltFile.read()
    
def deriveKey(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
    return kdf.derive(password.encode())

def generateKey(password, salt):
    #generate key from salt and password and encode it using Base 64
    logging.info("Deriving Criptography key from password\n")
    derived_key = deriveKey(salt, password)
    return base64.urlsafe_b64encode(derived_key)

def getFileContent(filename):
    with open(filename, "rb") as readfile:
        return readfile.read()

def setFileContent(filename, data):
    with open(filename, "wb") as writefile:
        writefile.write(data)

def encrypt(filepath, cryptographyObject):
    encrypted_data = cryptographyObject.encrypt(getFileContent(filepath))
    setFileContent(filepath, encrypted_data)
    logging.info(f"File {filepath} ENCRYPTED\n")

def decrypt(filepath, pwd):
    if checkPassword(pwd):
        key = generateKey(pwd, loadSalt())
        cryptographyObject = Fernet(key)
        try:
            decrypted_data = cryptographyObject.decrypt(getFileContent(filepath))
            setFileContent(filepath, decrypted_data)
            logging.info(f"File {filepath} DECRYPTED\n")
        except:
            encrypt(filepath, cryptographyObject)
    else:
        logging.error("WRONG PASSWORD\n")

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

print("\nChoose an option:")
print("1. Set/Reset a password for cryptography;")
print("2. Encrypt/Decrypt file;")
print("0. End program.\n")

opcao = int(input("Option: "))
while opcao not in [0, 1, 2]:
    logging.warning("INVALID OPTION!")
    opcao = int(input("Option: "))

if opcao == 1:
    resetPassword()
elif opcao == 2:
    file = input("Type the full path of the file to be encrypted/decrypted (file included): ")
    pwd = getpass.getpass("Type your password: ")
    decrypt(file, pwd)

print("\n*************** End of program ***************")
