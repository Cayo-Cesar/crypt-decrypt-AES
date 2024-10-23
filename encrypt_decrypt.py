import tkinter
from tkinter import ttk
import tkinter.messagebox
import tkinter.filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
#from main import main_menu


def aes_menu():
    window = tkinter.Tk()
    window.title("AES")
    window.geometry("300x300")

    def encrypt_aes():
        return

    def decrypt_aes():
        return

    style = ttk.Style()

    
    label_title = ttk.Label(window, text="AES Encryption/Decryption", anchor="center")
    label_title.pack(pady=20)

    style.configure("TButton", font=("Arial", 12), padding=10)
    style.configure("TLabel", font=("Arial", 16), padding=10)

    button_encrypt = ttk.Button(window, text="Cifrar", command=encrypt_aes, width=30)
    button_encrypt.pack(pady=10)

    button_decrypt = ttk.Button(window, text="Decifrar", command=decrypt_aes, width=30)
    button_decrypt.pack(pady=10)

    return


