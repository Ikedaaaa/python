import os

# Generate 100 KB file
with open('teste100kb.txt', "w") as file100kb:
    file100kb.write("0"*100)
    file100kb.write("\n\n")

while os.path.getsize("./teste100kb.txt") < (100*1024):
    with open('teste100kb.txt', "a") as file100kb:
        file100kb.write("0"*100)
        file100kb.write("\n\n")

# Generate 1 MB file
with open('teste1mb.txt', "w") as file1mb:
    file1mb.write("1"*1000)
    file1mb.write("\n")

char = 0
while os.path.getsize("./teste1mb.txt") < (1*1024*1024):
    with open('teste1mb.txt', "ab") as file1mb:
        file1mb.write((chr(char)*1000).encode())
        file1mb.write(b'\r\n')
    char = (char + 1) if (char < 1114111) else 0
    if char in [10, 13]:
        char += 1

# Generate 11MB file
with open('teste11mb.txt', "w") as file10mb:
    file10mb.write("2"*1000)
    file10mb.write("\n")

char = 0
while os.path.getsize("./teste11mb.txt") < ((11*1024)*1024):
    with open('teste11mb.txt', "ab") as file10mb:
        file10mb.write((chr(char)*1000).encode())
        file10mb.write(b'\r\n')
    char = (char + 1) if (char < 1114111) else 0
    if char in [10, 13]:
        char += 1

# Generate 102MB file
with open('teste102mb.txt', "w") as file102mb:
    file102mb.write("3"*1000)
    file102mb.write("\n")

char = 0
while os.path.getsize("./teste102mb.txt") < ((102*1024)*1024):
    with open('teste102mb.txt', "ab") as file102mb:
        file102mb.write((chr(char)*1000).encode())
        file102mb.write(b'\r\n')
    char = (char + 1) if (char < 1114111) else 0
    if char in [10, 13]:
        char += 1

# Generate 600MB file
with open('teste600mb.txt', "w") as file600mb:
    file600mb.write("4"*1000)
    file600mb.write("\n")

char = 0
error_chars = []
while os.path.getsize("./teste600mb.txt") < ((600*1024)*1024):
    with open('teste600mb.txt', "ab") as file600mb:
        try:
            file600mb.write((chr(char)*1000).encode())
            file600mb.write(b'\r\n')
        except:
            error_chars.append(char)
            pass
    char = (char + 1) if (char < 1114111) else 0
    if char in [10, 13]:
        char += 1
    elif 55296 <= char <= 57343:
        char = 57344

if len(error_chars) > 0:
    with open('error_chars.txt', "w") as error_file:
        error_file.write("\n".join(map(str, error_chars)))
