from cryptography.fernet import Fernet
import hashlib

def generateKeyFile():
    key = Fernet.generate_key()
    print("Key type:", type(key))
    with open("key.key", "wb") as keyFile:
        keyFile.write(key)

def getKeyFromFile():
    with open("key.key", "rb") as keyFile:
        return keyFile.read()

def setPassword():
    senha1 = input("\nDigite uma senha: ")
    senha2 = input("Confirme sua senha: ")

    while senha1 != senha2:
        print("\nAS SENHAS NÃO CONFEREM\n")
        senha1 = input("Digite uma senha: ")
        senha2 = input("Confirme sua senha: ")

    with open("password.hash", "wb") as pwdFile:
        pwdFile.write(hashlib.sha256(senha1.encode("utf-8")).hexdigest().encode())

    print("\nNova senha definida com sucesso\n")

def resetPassword():
    try:
        password_hash = "".encode()
        with open("password.hash", "rb") as pwdFile:
            password_hash = pwdFile.read()

        password_old = input("\nDigite sua senha antiga: ")
        password_old_hash = hashlib.sha256(password_old.encode("utf-8")).hexdigest().encode()

        if password_old_hash == password_hash:
            print("\nRedefinição de senha:")
            setPassword()
        else:
            print("\nAS SENHAS NÃO CONFEREM")
        
    except FileNotFoundError:
        setPassword()

def getFileContent(filename):
    with open(filename, "rb") as readfile:
        return readfile.read()

def setFileContent(filename, data):
    with open(filename, "wb") as writefile:
        writefile.write(data)
    print(f"Saved changes to file {filename}\n")

def encrypt(filepath, key):
    cryptographyObject = Fernet(key)

    encrypted_data = cryptographyObject.encrypt(getFileContent(filepath))
    setFileContent(filepath, encrypted_data)

def decrypt(filepath, key):
    cryptographyObject = Fernet(key)

    decrypted_data = cryptographyObject.decrypt(getFileContent(filepath))
    setFileContent(filepath, decrypted_data)

if (int(input("Generate new key? (0 - No | 1 - Yes) ")) > 0):
    generateKeyFile()
    print("New key generated\n")

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
    key = getKeyFromFile()
    file = input("Type the full path of the file to be encrypted (file included): ")

    encrypt(file, key)

    key = getKeyFromFile()
    file = input("Type the full path of the file to be decrypted (file included): ")

    decrypt(file, key)

print("\n*************** End of program ***************")
