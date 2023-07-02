from cryptography.fernet import Fernet

def generateKeyFile():
    key = Fernet.generate_key()
    print("Key type:", type(key))
    with open("key.key", "wb") as keyFile:
        keyFile.write(key)

def getKeyFromFile():
    with open("key.key", "rb") as keyFile:
        return keyFile.read()

def saveTextToFile(string):
    with open("cryptography_test.txt", "wb") as cryptographyTestFile:
        cryptographyTestFile.write(string)
    print("Text saved to file cryptography_test.txt\n")

def getEncryptedTextFromFile():
    with open("cryptography_test.txt", "rb") as cryptographyTestFile:
        return cryptographyTestFile.read()

if (int(input("Generate new key? (0 - No | 1 - Yes) ")) > 0):
    generateKeyFile()
    print("New key generated\n")

if (int(input("Encrypt text? (0 - No | 1 - Yes) ")) > 0):
    key = getKeyFromFile()
    print("Key type:", type(key))
    print(f"Encryption key: {key}\n") #Just for test purposes
    text = input("Type some text to be encrypted: ").encode()
    print("Text type:", type(text))

    #Initialize the Fernet class
    cryptographyObject = Fernet(key)
    encryptedText = cryptographyObject.encrypt(text)
    print("Encrypted text type:", type(encryptedText))
    print(f"Encrypted text: {encryptedText}\n")
    saveTextToFile(encryptedText)

if (int(input("Decrypt text? (0 - No | 1 - Yes) ")) > 0):
    key = getKeyFromFile()
    print(f"Encryption key: {key}\n") #Just for test purposes
    encryptedText = getEncryptedTextFromFile()
    print("Encrypted text type:", type(encryptedText))

    cryptographyObject = Fernet(key)
    decryptedText = cryptographyObject.decrypt(encryptedText)
    print("Decrypted text type:", type(decryptedText))
    print(f"Decrypted text: {decryptedText}\n")
    saveTextToFile(decryptedText)

print("\n*************** End of program ***************")
