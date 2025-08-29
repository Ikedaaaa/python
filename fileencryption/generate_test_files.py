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
    file1mb.write("0"*5000)
    file1mb.write("\n\n")

while os.path.getsize("./teste1mb.txt") < (1*1024*1024):
    with open('teste1mb.txt', "a") as file1mb:
        file1mb.write("0"*5000)
        file1mb.write("\n\n")

# Generate 11MB file
with open('teste11mb.txt', "w") as file10mb:
    file10mb.write("a"*5000)
    file10mb.write("\n\n")

while os.path.getsize("./teste11mb.txt") < ((11*1024)*1024):
    with open('teste11mb.txt', "a") as file10mb:
        file10mb.write("a"*5000)
        file10mb.write("\n\n")

# Generate 110MB file
with open('teste110mb.txt', "w") as file10mb:
    file10mb.write("a"*5000)
    file10mb.write("\n\n")

while os.path.getsize("./teste110mb.txt") < ((110*1024)*1024):
    with open('teste110mb.txt', "a") as file10mb:
        file10mb.write("a"*5000)
        file10mb.write("\n\n")
