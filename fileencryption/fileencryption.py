from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from tkinter import filedialog

import base64
import getpass
import bcrypt
import logging
import subprocess
import configparser
import tkinter

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

    workFactor = int(input("Salt work factor (0 to use the standard = 12): "))
    salt = generateSalt((workFactor if workFactor > 0 else 12))

    logging.info(f"Generating new Bcrypt hash with Work Factor of {(workFactor if workFactor > 0 else 12)}\n")
    with open("password.hash", "wb") as pwdFile:
        pwdFile.write(bcrypt.hashpw(senha1.encode(), salt))

    logging.info("New password set successfully\n")

def resetPassword():
    qtnEncryptedFiles = getQtnEncryptedFiles()
    try:
        password_hash = getPassword()

        if qtnEncryptedFiles <= 0:
            password_old = getpass.getpass("\nType your old password: ")

            if checkPassword(password_old, password_hash):
                print("****** Reset password ******")
                setPassword()
            else:
                logging.error("PASSWORDS DON'T MATCH")
        else:
            logging.error(f"{encryptedFilesStr(qtnEncryptedFiles)} decrypt them before resetting your password")
            changePwdWithEncryptedFilesInfo()
    except FileNotFoundError:
        if qtnEncryptedFiles > 0:
            logging.warning(f"{encryptedFilesStr(qtnEncryptedFiles)} but the password.hash file appears to be missing. Make sure to set the exact password that was used to encrypt these files previously\n")
            changePwdWithEncryptedFilesInfo()
        setPassword()

def checkPassword(password_input, password_old_hash=""):
    logging.info(f"Checking Password\n")
    password_hash = getPassword() if password_old_hash == "" else password_old_hash
    return bcrypt.checkpw(password_input.encode(), password_hash)

def generateSalt(work_factor):
    return bcrypt.gensalt(rounds=work_factor)
    
def deriveKey(password):
    salt = Scrypt(salt=b'', length=16, n=2**19, r=8, p=1).derive(password.encode())
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=12,
        lanes=4,
        memory_cost=2**21,
        ad=None,
        secret=None,
    )
    return kdf.derive(password.encode())

def generateKey(password):
    #generate key from salt and password and encode it using Base 64
    logging.info("Deriving Criptography key from password\n")
    derived_key = deriveKey(password)
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
    setQtnEncryptedFiles(getQtnEncryptedFiles() + 1)
    logging.info(f"File {filepath} ENCRYPTED\n")

def decrypt(files, pwd, openAfterDecryption=False):
    triedToOpenNotEncryptedFile = False
    if checkPassword(pwd):
        key = generateKey(pwd)
        cryptographyObject = Fernet(key)
        for filepath in files:
            try:
                decrypted_data = cryptographyObject.decrypt(getFileContent(filepath))
                setFileContent(filepath, decrypted_data)
                qtnEncryptedFiles = getQtnEncryptedFiles()
                setQtnEncryptedFiles(((qtnEncryptedFiles - 1) if qtnEncryptedFiles > 1 else 0))
                logging.info(f"File {filepath} DECRYPTED\n")
            except:
                if not openAfterDecryption:
                    encrypt(filepath, cryptographyObject)
                else:
                    triedToOpenNotEncryptedFile = True
                    logging.error("TO USE THIS OPTION, THE FILE NEEDS TO BE ENCRYPTED\n")
            finally:
                if openAfterDecryption and not triedToOpenNotEncryptedFile:
                    openFileAfterDecryption(filepath, cryptographyObject)
    else:
        logging.error("WRONG PASSWORD\n")

def getQtnEncryptedFiles():
    try:
        with open("encryptedfiles.ctrl", "rb") as encryptedfiles_file:
            return int(encryptedfiles_file.read().decode())
    except FileNotFoundError:
        setQtnEncryptedFiles(0)
        return 0

def setQtnEncryptedFiles(qtnEncryptedFiles):
    with open("encryptedfiles.ctrl", "wb") as encryptedfiles_file:
        encryptedfiles_file.write(str(qtnEncryptedFiles).encode())

def encryptedFilesStr(x):
    return f"There are {x} encrypted files in your computer,"

def changePwdWithEncryptedFilesInfo():
    logging.info(f"Decryption won't work if you change the password because the key used for encryption will not be the same")

def getFileExtension(file_name):
    return file_name.split(".")[-1].lower()

def getProcessToRun(file_path):
    config_parser = configparser.RawConfigParser()
    config_parser.read(r'programs-to-open-files.cfg')

    if config_parser.has_section('PROGRAMS'):
        notepad_path = config_parser.get('PROGRAMS', 'txt')
        if len(notepad_path) == 0:
            notepad_path = 'notepad.exe'
        
        pdf_path = config_parser.get('PROGRAMS', 'pdf')
        if len(pdf_path) == 0:
            pdf_path = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'

        word_path = config_parser.get('PROGRAMS', 'docx')
        if len(word_path) == 0:
            word_path = 'C:/Program Files/Microsoft Office/root/Office16/winword.exe'

        excel_path = config_parser.get('PROGRAMS', 'excel')
        if len(excel_path) == 0:
            excel_path = 'C:/Program Files/Microsoft Office/root/Office16/excel.exe'
    else:
        notepad_path = 'notepad.exe'
        pdf_path = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
        word_path = 'C:/Program Files/Microsoft Office/root/Office16/winword.exe'
        excel_path = 'C:/Program Files/Microsoft Office/root/Office16/excel.exe'
    
    processes_list = [
        [['txt'], notepad_path], 
        [['pdf'], pdf_path],
        [['docx', 'doc'], word_path],
        [['xlsx', 'xls', 'csv'], excel_path]
    ]
    file_extension = getFileExtension(file_path)
    for process in processes_list:
        if file_extension in process[0]:
            return True, file_extension, process[1]
    return False, file_extension, 'File extension not supported yet'

def openFileAfterDecryption(file_path, cryptography_object):
    try:
        fileExtensionSupported, fileExtension, process = getProcessToRun(file_path)
        if fileExtensionSupported:
            subprocess.run([process, file_path])
            if fileExtension == 'pdf':
                logging.warning("A pdf file doesn't wait for the process to be terminated before continuing the execution of the code.")
                print("An input() was used to prevent the file from being encrypted immediately after trying to open it.")
                print("The pdf would be encrypted again before the application could even load it.\n")
                input("Press Enter to continue...")
        else:
            logging.error(f"{process}: {fileExtension}\n")
    finally:
        encrypt(file_path, cryptography_object)

def onSelectEncryptionOption(option, open_after_decryption=False):
    files = []
    input_multiple_files = False
    option_word = ("ENCRYPTED" if option == 2 else "DECRYPTED")

    get_files_using_file_picker = int(input(f"\nType \"1\" to select the file(s) to be {option_word} using the file picker.\nType any other number to input the file(s) path(s) manually: ")) == 1

    if not get_files_using_file_picker:
        input_str_mf = f"\nType \"1\" if you wish to {option_word[:7]} multiple files. Type any other number for single file: "
        input_str_uf = f"\nType \"1\" if you have the files to be {option_word} in a txt file. Type any other number to enter the files manually: "
        input_str_ef = f"\nEnter the path of the file and the file containing the files to be {option_word} (e.g.: C:/Users/names.txt): "

        if not open_after_decryption:
            input_multiple_files = int(input(input_str_mf)) == 1

        input_str_tf = f"\nType the full path of the file{('s' if input_multiple_files else '')} to be {option_word} (file included)"

        if input_multiple_files:
            input_files_using_file = int(input(input_str_uf)) == 1

            if input_files_using_file:
                names_file_path = input(input_str_ef)

                with open(names_file_path, "r") as names_file:
                    file = names_file.readline().rstrip()
                    while file != "":
                        files.append(file)
                        file = names_file.readline().rstrip()
            else:
                print(input_str_tf)

                i = 1
                print("Type \"0\" to stop inputting files\n")
                file_path_input = input(f"File {i}: ")
                
                while file_path_input != "0":
                    files.append(file_path_input)
                    i += 1
                    file_path_input = input(f"File {i}: ")
        else:
            print(input_str_tf)
            files.append(input("\nFile path: "))
    else:
        if open_after_decryption:
            files.append(filedialog.askopenfilename())
        else:
            files = list(filedialog.askopenfilenames())

    pwd = getpass.getpass("Type your password: ")

    if len(files) > 0:
        decrypt(files, pwd, open_after_decryption)
    else:
        logging.error("No file was inputted!\n")

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)
tkinter.Tk().withdraw()

print("\nChoose an option:")
print("1. Set/Reset a password for cryptography;")
print("2. Encrypt file(s) (allows input of multiple files);")
print("3. Decrypt file(s) (allows input of multiple files);")
print("4. Decrypt file and open it. When you close it, encrypt it again;")
print("0. End program.\n")

opcao = int(input("Option: "))
while opcao not in [0, 1, 2, 3, 4]:
    logging.warning("INVALID OPTION!")
    opcao = int(input("Option: "))

if opcao == 1:
    resetPassword()
elif opcao == 2:
    onSelectEncryptionOption(opcao)
elif opcao == 3:
    onSelectEncryptionOption(opcao)
elif opcao == 4:
    onSelectEncryptionOption(opcao, True)

print("\n*************** End of program ***************")

input("\nPress Enter to end this program")
