import tkinter
from tkinter import *
import base64
from tkinter import messagebox


screen = tkinter.Tk()
screen.title(" Secret Notes")
screen.maxsize(height=600, width=300)
screen.minsize(height=600, width=300)


photo = PhotoImage(file="8414550.png")
photo_label = Label(image=photo,height=128,width=128)
photo_label.pack()

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def clicked():
    Input = title_entry.get()
    Inputtext = secret_text.get("1.0", 'end-1c')
    FileName = str("" + Input + ".txt")
    key = key_entry.get()
    if len(Input) == 0 or len(Inputtext) == 0 or len(key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(key, Inputtext)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{Input}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{Input}\n{message_encrypted}')
        finally:
            title_entry.delete(0, END)
            key_entry.delete(0, END)
            secret_text.delete("1.0", END)


def decrypt_text():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")



title_label = tkinter.Label(text="Text Your Title", font=30)
title_label.pack()

title_entry = tkinter.Entry(screen)
title_entry.pack()

secret_label = tkinter.Label(text="Enter Your Secret", font=30)
secret_label.pack()

secret_text = tkinter.Text(height=18, width=30)
secret_text.pack()

key_label = tkinter.Label(text="Enter Key")
key_label.pack()

key_entry = tkinter.Entry()
key_entry.pack()

save_button = tkinter.Button(screen, text=" Save & Encrypt ", command=clicked)
save_button.pack()

Decrypt_button = tkinter.Button(text=" Decrypt ",command=decrypt_text)
Decrypt_button.pack()

screen.mainloop()
