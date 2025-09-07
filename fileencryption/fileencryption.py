from aes256_cbc import AES256_CBC
from aes256_gcm import AES256_GCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from tkinter import filedialog, Tk
from configparser import RawConfigParser

from getpass import getpass
from bcrypt import hashpw, checkpw, gensalt
from subprocess import run
from secrets import token_bytes
from hashlib import sha256, sha512
from time import sleep, perf_counter_ns
from gc import collect
from os.path import dirname, getsize
from os import fdopen, fsync, replace, remove
from tempfile import mkstemp
from multiprocessing import Pool

import logging
import ctypes

LARGE_FILE_SIZE = ((100*1024)*1024) # 100 MiB. Minimum size for files to be considered large

if __name__ == "__main__":
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    hwnd = kernel32.GetConsoleWindow()

    config_parser = RawConfigParser()
    config_parser.read(r'config.cfg')

    if config_parser.has_section('GENERAL'):
        time_ctrl = int(config_parser.get('GENERAL', 'time_ctrl')) > 0
        file_input_method = int(config_parser.get('GENERAL', 'file_input'))
    else:
        time_ctrl = False
        file_input_method = 0

    def set_focus():
        sleep(0.1)
        user32.SetForegroundWindow(hwnd)

    root = Tk()
    root.withdraw()
    set_focus()
    root.destroy()

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

def getPassword():
    with open("password.hash", "rb") as pwdFile:
        return pwdFile.read()
    
def generateSalt(work_factor):
    return gensalt(rounds=work_factor)

def setPassword(hashes=[]):
    try:
        senha1 = bytearray(getpass("\nType your new password: ").encode())
        senha2 = bytearray(getpass("Confirm your new password: ").encode())

        while senha1 != senha2:
            logging.warning("THE PASSWORDS DON'T MATCH\n")
            senha1 = bytearray(getpass("Type your new password: ").encode())
            senha2 = bytearray(getpass("Confirm your new password: ").encode())

        workFactor = int(input("Salt work factor (0 to use the standard = 12): "))
        bcrypt_header_salt = generateSalt((workFactor if workFactor > 0 else 12))
        salt = bcrypt_header_salt.split(b'$')[-1]
        sha512_hash = sha512(salt + bytes(senha1)).digest()

        logging.info(f"Generating new Bcrypt hash with Work Factor of {(workFactor if workFactor > 0 else 12)}\n")
        hashes.append(hashpw(sha512_hash, bcrypt_header_salt))
        save_password_to_file(hashes)

        logging.info("New password set successfully\n")
    finally:
        clear_bytearray(senha1)
        clear_bytearray(senha2)
        senha1 = senha2 = sha512_hash = None
        del senha1, senha2, sha512_hash
        collect()

def save_password_to_file(hashes_list):
    with open("password.hash", "wb") as pwdFile:
        for idx, hash in enumerate(hashes_list):
            if idx > 0:
                pwdFile.write(b'\r\n')
            pwdFile.write(hash)

def resetPassword():
    set_same_pwd_str = "Make sure to set the exact password that was used to encrypt these files previously"
    qtnEncryptedFiles = getQtnEncryptedFiles()
    try:
        hashes_list = getPassword().split(b'\r\n')
        valid_hashes = [valid_hash for valid_hash in hashes_list if len(valid_hash) == 60]
        if len(valid_hashes) == len(hashes_list):
            reset_pwd = True
            add_password = False
            delete_password = False
            if len(hashes_list) < 2:
                print("\nDo you want to add another password or change the current one?")
                add_password = (int(input("Type \"1\" to add another password. Type any other number to reset the current one: ")) == 1)
                reset_pwd = not add_password
            else:
                print("\nDo you want to delete one of the passwords or change one of them?")
                delete_password = (int(input("Type \"1\" to delete a password. Type any other number to reset one of them: ")) == 1)
                reset_pwd = not delete_password
            
            if (qtnEncryptedFiles > 0) and (reset_pwd or delete_password):
                logging.warning(f"{encryptedFilesStr(qtnEncryptedFiles)}")
                changePwdWithEncryptedFilesInfo()
                print("Are you sure you want to proceed?")
                if (int(input("Type \"1\" to continue. Type any other number to abort: ")) != 1):
                    return
                
            if add_password:
                setPassword(hashes=valid_hashes)
            else:
                try:
                    input_str_pwd = ("\nType your old password: " if reset_pwd else "\nType the password you want to delete: ")
                    password_input = bytearray(getpass(input_str_pwd).encode())

                    logging.info(f"Checking Password\n")
                    password_match, matched_hash = check_password_in_parallel(password_input, valid_hashes)
                    
                    if password_match:
                        valid_hashes.remove(matched_hash)
                        if reset_pwd:
                            print("****** Reset password ******")
                            setPassword(hashes=valid_hashes)
                        elif delete_password:
                            save_password_to_file(valid_hashes)
                            logging.info("Password successfully deleted\n")
                    else:
                        logging.error("PASSWORDS DON'T MATCH")
                finally:
                    clear_bytearray(password_input)
                    password_input = None
                    del password_input
                    collect()
        else:
            logging.warning("Invalid hash in the password.hash file. You will have to set a new password.\n")
            if qtnEncryptedFiles > 0:
                logging.warning(f"{encryptedFilesStr(qtnEncryptedFiles)}")
                logging.warning(f"{set_same_pwd_str}\n")
            setPassword(hashes=valid_hashes)
            
    except FileNotFoundError:
        if qtnEncryptedFiles > 0:
            logging.warning(f"{encryptedFilesStr(qtnEncryptedFiles)} but the password.hash file appears to be missing. {set_same_pwd_str}\n")
            changePwdWithEncryptedFilesInfo()
        setPassword()

def check_password_in_parallel(password_input, hashes):
    pool = Pool()
    sha512_hash = get_sha512_hash(password_input, hashes[0])
    sha512_2_hash = None
    try:
        result1 = pool.apply_async(checkpw, [sha512_hash, hashes[0]])
        result2 = None
        if len(hashes) > 1:
            sha512_2_hash = get_sha512_hash(password_input, hashes[1])
            result2 = pool.apply_async(checkpw, [sha512_2_hash, hashes[1]])
        pool.close()
        answer1 = result1.get(timeout=60)

        answer2 = False
        if len(hashes) > 1:
            answer2 = result2.get(timeout=60)

        if answer1:
            return True, hashes[0]
        if answer2:
            return True, hashes[1]
        return False, None
    except Exception as e:
        raise e
    finally:
        pool.terminate()
        pool = sha512_hash = sha512_2_hash = None
        del pool, sha512_hash, sha512_2_hash
        collect()

def get_sha512_hash(password_input, hash):
    salt = hash.split(b'$')[-1][:22]
    return sha512(salt + bytes(password_input)).digest()

def deriveKey(p_salt, password):
    kdf = Argon2id(
        salt=p_salt,
        length=64,
        iterations=10,
        lanes=4,
        memory_cost=2**21,
        ad=None,
        secret=None,
    )
    return kdf.derive(bytes(password))

def generateKey(p_salt, password):
    #generate key from salt and password
    logging.info("Deriving Criptography key from password\n")
    
    if time_ctrl:
        t1 = perf_counter_ns()
    
    derived_key = deriveKey(p_salt, password)

    if time_ctrl:
        t2 = perf_counter_ns()
        log_time_ctrl(t1, t2, "Derive key")
    
    return derived_key

def get_file_bytes(filename, bytes_to_read, bytes_to_start=None):
    with open(filename, "rb") as readfile:
        if bytes_to_start and (bytes_to_start > 0):
            readfile.seek(bytes_to_start)
        return readfile.read(bytes_to_read)

def getFileContent(filename):
    with open(filename, "rb") as readfile:
        return readfile.read()

def setFileContent(src_file, data):
    dir_name = dirname(src_file) or "."
    fd, tmp_path = mkstemp(dir=dir_name)
    try:
        with fdopen(fd, "wb") as tmp_file:
            tmp_file.write(data)
            tmp_file.flush()
            fsync(tmp_file.fileno())  # ensure data is on disk
        
        replace(tmp_path, src_file)
    except Exception:
        try:
            remove(tmp_path)
        except OSError:
            pass
        raise

def add_header(p_salt):
    salt_hash = sha256(p_salt).digest()
    return (salt_hash + p_salt)

def aes256_cbc_encryption(aes256, file, salt):
    encrypted_data = aes256.encrypt(getFileContent(file))
    data_with_header = add_header(salt) + encrypted_data
    setFileContent(file, data_with_header)

def encrypt(pwd, files):
    input_text = f"\nType \"1\" to generate a new salt and key for each file.\nType any other number to use the same: "
    new_salt_each_file = (True if (len(files) <= 1) else (int(input(input_text)) == 1))

    salt = token_bytes(16)
    key = bytearray(generateKey(salt, pwd))
    try:
        aes256_cbc = AES256_CBC(bytes(key))
        aes256_gcm = AES256_GCM(bytes(key), salt)
        is_large_file = (getsize(files[0]) >= LARGE_FILE_SIZE)
        for idx, filepath in enumerate(files):
            try:
                aes256 = (aes256_gcm if is_large_file else aes256_cbc)
                if key:
                    clear_bytearray(key)
                    key = None
                    collect()

                if not is_large_file:
                    aes256_cbc_encryption(aes256, filepath, salt)
                else:
                    aes256.encrypt(filepath)
                
                setQtnEncryptedFiles(getQtnEncryptedFiles() + 1)
                logging.info(f"File {filepath} ENCRYPTED\n")
                
                if (idx < (len(files) - 1)):
                    is_large_file = (getsize(files[idx+1]) >= LARGE_FILE_SIZE)
                    if new_salt_each_file:
                        salt = token_bytes(16)
                        key = bytearray(generateKey(salt, pwd))
                        
                        if is_large_file:
                            aes256_gcm = AES256_GCM(bytes(key), salt)
                        else:
                            aes256_cbc = AES256_CBC(bytes(key))
            except Exception as e:
                raise e
    finally:
        if key:
            clear_bytearray(key)
        key = aes256_cbc = aes256_gcm = None
        del key, aes256_cbc, aes256_gcm
        collect()
        
def get_salt_from_file(file):
    header = get_file_bytes(file, 48)
    if len(header) != 48:
        return b''
    
    salt_hash_file = header[:32]
    salt = header[32:]
    salt_hash = sha256(salt).digest()
    if salt_hash_file != salt_hash:
        return b''

    return salt

def get_encryption_mode_and_version(file):
    header = get_file_bytes(file, 9, 48)

    if len(header) > 0:
        if ((header[0] == 0x03) and (header[1] == 0x02) and (header[2] == 0x03)) and (header[3] == 0x01):
            return 'CBC', 1
        
        if ((header[0] == 0x07) and (header[1] == 0x03) and (header[2] == 0x0D)) and (header[3] == 0x01):
            return 'GCM', 1
    
    return '', 0
    
def clear_bytearray(bytearray_object):
    for i in range(len(bytearray_object)):
        bytearray_object[i] = 0

def decrypt(pwd, files, option):
    salts_dict = {}
    file_decrypted = False
    try:
        for filepath in files:
            salt = get_salt_from_file(filepath)
            encryption_mode, version = get_encryption_mode_and_version(filepath)
            if (len(salt) == 16) and (encryption_mode != '') and (version > 0):
                try:
                    key = bytearray(salts_dict.get(salt, b''))
                    
                    if not key:
                        key = bytearray(generateKey(salt, pwd))
                        salts_dict[salt] = key

                    if (encryption_mode == 'CBC') and (version == 1):
                        aes256 = AES256_CBC(bytes(key))
                        data = getFileContent(filepath)[48:]
                        decrypted_data = aes256.decrypt(data)
                        setFileContent(filepath, decrypted_data)
                    elif (encryption_mode == 'GCM') and (version == 1):
                        aes256 = AES256_GCM(bytes(key), b'')
                        aes256.decrypt(filepath)
                    
                    qtnEncryptedFiles = getQtnEncryptedFiles()
                    setQtnEncryptedFiles(((qtnEncryptedFiles - 1) if qtnEncryptedFiles > 1 else 0))
                    logging.info(f"File {filepath} DECRYPTED\n")
                    file_decrypted = True
                except Exception as e:
                    raise e
            else:
                logging.error(f"FILE \"{filepath}\" NOT ENCRYPTED")
                logging.error(f"OR")
                logging.error(f"FILE HAS BEEN TAMPERED WITH\n")
    finally:    
        for s, k in salts_dict.items():
            clear_bytearray(k)
            k = None
        salts_dict.clear()
        salts_dict = None
        del salts_dict
        collect()

    if file_decrypted and (option == 4):
        openFileAfterDecryption(files[0], pwd)

def encrypt_decrypt(files, pwd, selected_option):
    if time_ctrl:
        t1 = perf_counter_ns()

    hashes_list = getPassword().split(b'\r\n')
    valid_hashes = [valid_hash for valid_hash in hashes_list if len(valid_hash) == 60]
    if len(valid_hashes) == 0:
        logging.error("No valid password hash found.\n")
    else:
        if len(valid_hashes) != len(hashes_list):
            logging.warning("There is an invalid hash in the password.hash file.\n")
        logging.info(f"Checking Password\n")

        if check_password_in_parallel(pwd, valid_hashes)[0]:
            if time_ctrl:
                t2 = perf_counter_ns()
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
            run([process, file_path])
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

    get_files_using_file_picker = (file_input_method == 2)

    if (file_input_method not in [1, 2]):
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

    try:
        pwd = bytearray(getpass("Type your password: ").encode())

        if time_ctrl:
            t1 = perf_counter_ns()

        if len(files) > 0:
            encrypt_decrypt(files, pwd, option)
        else:
            logging.error("No file was inputted!\n")
    finally:    
        clear_bytearray(pwd)
        pwd = None
        del pwd
        collect()

    if time_ctrl:
        t2 = perf_counter_ns()
        log_time_ctrl(t1, t2, "Whole process")

if __name__ == "__main__":
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
