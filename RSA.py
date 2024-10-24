import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import tkinter
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
import binascii
import base64
import os

def rsa_menu():
    window = tk.Tk()
    window.title("Assinatura RSA")
    window.geometry("300x300")

    def sign_rsa():
        try:
            # Escolha do arquivo de entrada
            file_to_sign = filedialog.askopenfilename(title="Selecione o arquivo a ser assinado")
            if not file_to_sign:
                raise FileNotFoundError("Arquivo a ser assinado não foi selecionado.")

            # Escolha da chave privada
            private_key_file = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com a chave privada", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
            #private_key_file = filedialog.askopenfilename(title="Selecione o arquivo com a chave privada")
            if not private_key_file:
                raise FileNotFoundError("Arquivo com a chave privada não foi selecionado.")

            # Seleção da versão do SHA-2
            sha_version = simpledialog.askstring("Versão do SHA-2", "Escolha a versão do SHA-2 (256, 384, 512):")
            if sha_version not in ["256", "384", "512"]:
                raise ValueError("Versão inválida do SHA-2. Escolha entre 256, 384 ou 512.")

            # Escolha do formato de saída (Hex ou Base64)
            output_format = simpledialog.askstring("Formato de Saída", "Escolha o formato de saída (Hex ou Base64):").upper()
            if output_format not in ["HEX", "BASE64"]:
                raise ValueError("Formato de saída inválido. Escolha entre Hex ou Base64.")

            # Leitura da chave privada
            with open(private_key_file, "rb") as f_priv:
                private_key = RSA.import_key(f_priv.read())

            # Leitura do arquivo a ser assinado
            with open(file_to_sign, "rb") as f_file:
                message = f_file.read()

            # Escolha do algoritmo de hash SHA-2
            if sha_version == "256":
                h = SHA256.new(message)
            elif sha_version == "384":
                h = SHA384.new(message)
            elif sha_version == "512":
                h = SHA512.new(message)

            # Geração da assinatura
            signature = pkcs1_15.new(private_key).sign(h)

            # Conversão da assinatura para o formato desejado
            if output_format == "HEX":
                signature_out = binascii.hexlify(signature).decode()
            else:
                signature_out = base64.b64encode(signature).decode()

            # Salvando a assinatura em um arquivo
            current_directory = os.getcwd()
            with open(os.path.join(current_directory, "assinatura.txt"), "w") as f_sign:
                f_sign.write(signature_out)

            messagebox.showinfo("Sucesso", "Assinatura gerada e salva com sucesso!")

        except Exception as e:
            messagebox.showerror("Erro", str(e))

    style = ttk.Style()

    label_title = ttk.Label(window, text="Assinatura RSA", anchor="center")
    label_title.pack(pady=20)

    style.configure("TButton", font=("Arial", 12), padding=10)
    style.configure("TLabel", font=("Arial", 16), padding=10)

    button_sign = ttk.Button(window, text="Assinar", command=sign_rsa, width=30)
    button_sign.pack(pady=10)

    #window.mainloop()

# Chama o menu da assinatura
#rsa_sign_menu()
