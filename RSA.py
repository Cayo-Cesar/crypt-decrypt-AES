import tkinter as tk
from tkinter import ttk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64
import os

def rsa_menu():
    root = tk.Tk()
    root.title("RSA")
    root.geometry("300x300")

    def rsa_sign():
        try:
            # Obtém a chave privada
            with open("chave_privada.pem", "rb") as f:
                private_key_pem = f.read()
                private_key = RSA.import_key(private_key_pem)

            # Obtém a mensagem
            message = message_var.get().encode("utf-8")

            # Calcula o hash da mensagem
            h = SHA256.new(message)

            # Assina a mensagem
            signature = pkcs1_15.new(private_key).sign(h)

            # Codifica a assinatura em base64
            signature_b64 = base64.b64encode(signature).decode("utf-8")

            signature_var.set(signature_b64)

        except Exception as e:
            tk.messagebox.showerror("Erro", str(e))
    
    def rsa_verify():
        try:
            # Obtém a chave pública
            with open("chave_publica.pem", "rb") as f:
                public_key_pem = f.read()
                public_key = RSA.import_key(public_key_pem)

            # Obtém a mensagem
            message = message_var.get().encode("utf-8")

            # Calcula o hash da mensagem
            h = SHA256.new(message)

            # Obtém a assinatura
            signature = base64.b64decode(signature_var.get())

            # Verifica a assinatura
            pkcs1_15.new(public_key).verify(h, signature)

            tk.messagebox.showinfo("Sucesso", "Assinatura válida!")

        except Exception as e:
            tk.messagebox.showerror("Erro", str(e))

    return