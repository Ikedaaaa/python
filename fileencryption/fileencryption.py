from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import hashlib
import secrets
import base64

def getPassword():
    with open("password.hash", "rb") as pwdFile:
        return pwdFile.read()

def setPassword():
    senha1 = input("\nDigite uma senha: ")
    senha2 = input("Confirme sua senha: ")

    while senha1 != senha2:
        print("\nAS SENHAS NÃO CONFEREM\n")
        senha1 = input("Digite uma senha: ")
        senha2 = input("Confirme sua senha: ")

    if (int(input("Generate new salt? (0 - No | 1 - Yes) ")) > 0):
        saltSize = int(input("Salt size (0 to use standard the size 16): "))
        salt = generateSalt((saltSize if saltSize > 0 else 16))
        with open("salt.salt", "wb") as saltFile:
            saltFile.write(salt)
    else:
        salt = loadSalt()

    saltedPassword = senha1.encode("utf-8") + salt

    with open("password.hash", "wb") as pwdFile:
        pwdFile.write(hashlib.sha256(saltedPassword).hexdigest().encode())

    print("\nNova senha definida com sucesso\n")

def resetPassword():
    try:
        password_hash = getPassword()

        password_old = input("\nDigite sua senha antiga: ")
        salt = loadSalt()

        if checkPassword(password_old, salt, password_hash):
            print("\nRedefinição de senha:")
            setPassword()
        else:
            print("\nAS SENHAS NÃO CONFEREM")
        
    except FileNotFoundError:
        setPassword()

def checkPassword(password_input, salt, password_old_hash=""):
    password_hash = getPassword() if password_old_hash == "" else password_old_hash
    
    salted_password = password_input.encode("utf-8") + salt
    password_input_hash = hashlib.sha256(salted_password).hexdigest().encode()
    
    return password_input_hash == password_hash

def generateSalt(size):
    return secrets.token_bytes(size)

def loadSalt():
    with open("salt.salt", "rb") as saltFile:
        return saltFile.read()
    
def deriveKey(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
    return kdf.derive(password.encode())

def generateKey(password, salt): #, salt_size, generateSalt
    #generate key from salt and password and encode it using Base 64
    print("\nDeriving Criptography key from password\n")
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
    print(f"File {filepath} ENCRYPTED\n")

def decrypt(filepath, pwd):
    salt = loadSalt()
    if checkPassword(pwd, salt):
        key = generateKey(pwd, salt)
        cryptographyObject = Fernet(key)
        try:
            decrypted_data = cryptographyObject.decrypt(getFileContent(filepath))
            setFileContent(filepath, decrypted_data)
            print(f"File {filepath} DECRYPTED\n")
        except:
            encrypt(filepath, cryptographyObject)
    else:
        print("\nWARNING: Wrong Password\n")

print("\nEscolha uma opção:")
print("1. Definir/Redefinir senha para criptografia;")
print("2. Criptografar/Descriptografar arquivo;")
print("0. Encerrar programa.\n")

opcao = int(input("Opção: "))
while opcao not in [0, 1, 2]:
    print("OPÇÃO INVÁLIDA!")
    opcao = int(input("Opção: "))

if opcao == 1:
    resetPassword()
elif opcao == 2:
    file = input("Type the full path of the file to be encrypted/decrypted (file included): ")
    pwd = input("Type your password: ")
    decrypt(file, pwd)

print("\n*************** End of program ***************")
