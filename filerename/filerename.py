import os

def copy_file_names_to_txt_file():
    names_file_path = input("\nEnter the name of the file with its path you wish to copy the files' names to (e.g.: C:/Users/names.txt): ")
    save_full_path = (int(input("Type \"1\" if you wish to copy the full path of the files as well. Type any other number to copy only their names: ")) == 1)
    folder = input("Enter the path of the directory you want the files' names to be copied: ")

    with open(names_file_path, "w") as names_file:
        files = os.listdir(folder)
        for file in files:
            names_file.write(f"{((folder+'/') if save_full_path else '')}{file}\n")

def rename_files(rename_using_txt_file):
    folder = input("Enter the path of the directory you want the files to be renamed: ")

    if rename_using_txt_file:
        rename_files_using_txt_file(folder)
    else:
        rename_files_using_sequential_letters(folder)

def rename_files_using_txt_file(folder):
    names_file_path = input("\nEnter the path of the file (file included) with the names that will be used to rename the files in the folder entered previously: ")
    names_file_have_full_path = (int(input("Type \"1\" if the names file have the full path of each file. Type any other number if it's just their names: ")) == 1)
    
    with open(names_file_path, "r") as names_file:
        i = 0
        files = os.listdir(folder)
        name, ext = os.path.splitext(names_file.readline().rstrip())

        while (name != "") and (i < len(files)):
            filename, extension = os.path.splitext(files[i])
            source_file =f"{folder}/{filename}{extension}"
            renamed_file =f"{folder}/{os.path.basename(name) if names_file_have_full_path else name}{(extension if ext == '' else ext)}"
            
            os.rename(source_file, renamed_file)
            
            i += 1
            name, ext = os.path.splitext(names_file.readline().rstrip())

def rename_files_using_sequential_letters(folder):
    a = b = c = 97
    for file in os.listdir(folder):
        filename, extension = os.path.splitext(file)
        source_file =f"{folder}/{filename}{extension}"
        renamed_file =f"{folder}/file_{chr(a)}{chr(b)}{chr(c)}{extension}"
        
        os.rename(source_file, renamed_file)

        c += 1
        if c > 122:
            c = 97
            b += 1
            if b > 122:
                b = 97
                a += 1

print("\nChoose an option:")
print("1. Copy file names from a folder to a txt file;")
print("2. Rename files using names in a txt file;")
print("3. Rename files using a set of three letters starting from 'aaa' to 'zzz' ['aaa', 'aab', 'aac', ..., 'zzy', 'zzz'];")
print("0. End program.\n")

opcao = int(input("Option: "))
while opcao not in [0, 1, 2, 3]:
    print("INVALID OPTION!")
    opcao = int(input("Option: "))

if opcao == 1:
    copy_file_names_to_txt_file()
elif opcao in (2, 3):
    rename_files(opcao == 2)

print("\n*************** End of program ***************")
