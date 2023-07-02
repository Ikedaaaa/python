from cryptography.fernet import Fernet

def generateKeyFile():
    key = Fernet.generate_key()
    print("Key type:", type(key))
    with open("key.key", "wb") as keyFile:
        keyFile.write(key)

def getKeyFromFile():
    with open("key.key", "rb") as keyFile:
        return keyFile.read()

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

if (int(input("Encrypt file? (0 - No | 1 - Yes) ")) > 0):
    key = getKeyFromFile()
    file = input("Type the full path of the file to be encrypted (file included): ")

    encrypt(file, key)

if (int(input("Decrypt file? (0 - No | 1 - Yes) ")) > 0):
    key = getKeyFromFile()
    file = input("Type the full path of the file to be decrypted (file included): ")

    decrypt(file, key)

print("\n*************** End of program ***************")
