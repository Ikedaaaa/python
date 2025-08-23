from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from tkinter import filedialog

import base64
import getpass
import bcrypt
import logging
import subprocess
import configparser
import tkinter
import secrets
import hashlib
import time
import ctypes

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
hwnd = kernel32.GetConsoleWindow()

config_parser = configparser.RawConfigParser()
config_parser.read(r'config.cfg')

if config_parser.has_section('TIME'):
    time_ctrl = int(config_parser.get('TIME', 'time_ctrl')) > 0
else:
    time_ctrl = False

def set_focus():
    time.sleep(0.1)
    user32.SetForegroundWindow(hwnd)

root = tkinter.Tk()
root.withdraw()
set_focus()
root.destroy()

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
    
def deriveKey(p_salt, password):
    kdf = Argon2id(
        salt=p_salt,
        length=32,
        iterations=10,
        lanes=4,
        memory_cost=2**21,
        ad=None,
        secret=None,
    )
    return kdf.derive(password.encode())

def generateKey(p_salt, password):
    #generate key from salt and password and encode it using Base 64
    logging.info("Deriving Criptography key from password\n")
    
    if time_ctrl:
        t1 = time.perf_counter_ns()
    
    derived_key = deriveKey(p_salt, password)

    if time_ctrl:
        t2 = time.perf_counter_ns()
        log_time_ctrl(t1, t2, "Derive key")
    
    return base64.urlsafe_b64encode(derived_key)

def get_file_header(filename):
    with open(filename, "rb") as readfile:
        return readfile.read(108)

def getFileContent(filename):
    with open(filename, "rb") as readfile:
        return readfile.read()

def setFileContent(filename, data):
    with open(filename, "wb") as writefile:
        writefile.write(data)

def add_header_to_data(p_salt, data):
    b64_salt = base64.urlsafe_b64encode(p_salt)
    salt_hash = hashlib.sha256(b64_salt).hexdigest().encode()
    b64_hash = base64.urlsafe_b64encode(salt_hash)
    return (b64_hash[:86] + b64_salt[:22] + data)

def encrypt(pwd, files):
    new_salt_each_file = (True if (len(files) <= 1) else (int(input(f"\nType \"1\" to generate a new salt and key for each file.\nType any other number to use the same: ")) == 1))

    salt = secrets.token_bytes(16)
    key = bytearray(generateKey(salt, pwd))
    cryptographyObject = Fernet(bytes(key))

    for idx, filepath in enumerate(files):
        try:
            if key:
                clear_bytearray(key)
            encrypted_data = cryptographyObject.encrypt(getFileContent(filepath))
            data_with_header = add_header_to_data(salt, encrypted_data)
            setFileContent(filepath, data_with_header)
            setQtnEncryptedFiles(getQtnEncryptedFiles() + 1)
            logging.info(f"File {filepath} ENCRYPTED\n")
            
            if (idx < (len(files) - 1)) and new_salt_each_file:
                salt = secrets.token_bytes(16)
                key = bytearray(generateKey(salt, pwd))
                cryptographyObject = Fernet(bytes(key))
        except Exception as e:
            raise e
        
def get_salt_and_content_from_file(file):
    header = get_file_header(file)
    if len(header) != 108:
        return (b'', b'')
    
    b64_hash = header[:86] + b'=='
    b64_salt = header[86:] + b'=='

    try:
        hex_hash = base64.urlsafe_b64decode(b64_hash).decode()
    except:
        return (b'', b'')
    salt_hash = hashlib.sha256(b64_salt).hexdigest()

    if hex_hash != salt_hash:
        return (b'', b'')
    
    all_data = getFileContent(file)
    content = all_data[108:]

    return (base64.urlsafe_b64decode(b64_salt), content)

def clear_bytearray(bytearray_object):
    for i in range(len(bytearray_object)):
        bytearray_object[i] = 0

    bytearray_object = None

def decrypt(pwd, files, option):
    salts_dict = {}
    file_decrypted = False
    for filepath in files:
        salt, data = get_salt_and_content_from_file(filepath)
        if len(salt) == 16:
            key = bytearray(salts_dict.get(salt, b''))
            
            if not key:
                key = bytearray(generateKey(salt, pwd))
                salts_dict[salt] = key
            
            cryptographyObject = Fernet(bytes(key))
            try:
                decrypted_data = cryptographyObject.decrypt(data)
                setFileContent(filepath, decrypted_data)
                qtnEncryptedFiles = getQtnEncryptedFiles()
                setQtnEncryptedFiles(((qtnEncryptedFiles - 1) if qtnEncryptedFiles > 1 else 0))
                logging.info(f"File {filepath} DECRYPTED\n")
                file_decrypted = True
            except Exception as e:
                raise e
        else:
            logging.error(f"FILE \"{filepath}\" NOT ENCRYPTED\n")
    
    for s, k in salts_dict.items():
        clear_bytearray(k)
    
    salts_dict.clear()

    if file_decrypted and (option == 4):
        openFileAfterDecryption(files[0], pwd)

def encrypt_decrypt(files, pwd, selected_option):
    if time_ctrl:
        t1 = time.perf_counter_ns()
    
    if checkPassword(pwd):
        if time_ctrl:
            t2 = time.perf_counter_ns()
            log_time_ctrl(t1, t2, "Check password")
        
        if selected_option == 2:
            encrypt(pwd, files)
        else:
            decrypt(pwd, files, selected_option)
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

def log_time_ctrl(t1, t2, scope):
    nanosecs = (t2 - t1)
    logging.info(f"{scope}: {(nanosecs/1000000):.2f} milliseconds. {(nanosecs/1000000000):.4f} seconds")

def getFileExtension(file_name):
    return file_name.split(".")[-1].lower()

def getProcessToRun(file_path):
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

def openFileAfterDecryption(file_path, pwd):
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
        encrypt(pwd, [file_path])

def onSelectEncryptionOption(option):
    files = []
    input_multiple_files = False
    option_word = ("ENCRYPTED" if option == 2 else "DECRYPTED")

    get_files_using_file_picker = int(input(f"\nType \"1\" to select the file(s) to be {option_word} using the file picker.\nType any other number to input the file(s) path(s) manually: ")) == 1

    if not get_files_using_file_picker:
        input_str_mf = f"\nType \"1\" if you wish to {option_word[:7]} multiple files. Type any other number for single file: "
        input_str_uf = f"\nType \"1\" if you have the files to be {option_word} in a txt file. Type any other number to enter the files manually: "
        input_str_ef = f"\nEnter the path of the file and the file containing the files to be {option_word} (e.g.: C:/Users/names.txt): "

        if option != 4:
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
        if option == 4:
            files.append(filedialog.askopenfilename())
        else:
            files = list(filedialog.askopenfilenames())
        
        set_focus()

    pwd = bytearray(getpass.getpass("Type your password: ").encode())

    if time_ctrl:
        t1 = time.perf_counter_ns()

    if len(files) > 0:
        encrypt_decrypt(files, bytes(pwd).decode(), option)
    else:
        logging.error("No file was inputted!\n")
    
    clear_bytearray(pwd)
    del pwd

    if time_ctrl:
        t2 = time.perf_counter_ns()
        log_time_ctrl(t1, t2, "Whole process")

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

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
elif opcao in [2, 3, 4]:
    onSelectEncryptionOption(opcao)

print("\n*************** End of program ***************")

input("\nPress Enter to end this program")
