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
            file_to_sign = filedialog.askopenfilename(title="Selecione o arquivo a ser assinado")
            if not file_to_sign:
                raise FileNotFoundError("Arquivo a ser assinado não foi selecionado.")

            private_key_file = filedialog.askopenfilename(title="Selecione o arquivo com a chave privada (.pem):")
            if not private_key_file:
                raise FileNotFoundError("Arquivo com a chave privada não foi selecionado.")

            sha_version = simpledialog.askstring("Versão do SHA-2", "Escolha a versão do SHA-2 (256, 384, 512):")
            if sha_version not in ["256", "384", "512"]:
                raise ValueError("Versão inválida do SHA-2. Escolha entre 256, 384 ou 512.")

            output_format = simpledialog.askstring("Formato de Saída", "Escolha o formato de saída (Hex ou Base64):").upper()
            if output_format not in ["HEX", "BASE64"]:
                raise ValueError("Formato de saída inválido. Escolha entre Hex ou Base64.")

            with open(private_key_file, "rb") as f_priv:
                private_key = RSA.import_key(f_priv.read())

            with open(file_to_sign, "rb") as f_file:
                message = f_file.read()

            if sha_version == "256":
                h = SHA256.new(message)
            elif sha_version == "384":
                h = SHA384.new(message)
            elif sha_version == "512":
                h = SHA512.new(message)

            signature = pkcs1_15.new(private_key).sign(h)

            if output_format == "HEX":
                signature_out = binascii.hexlify(signature).decode()
                filename = "assinatura_hex.txt"
            else:
                signature_out = base64.b64encode(signature).decode()
                filename = "assinatura_base64.txt"

            with open(filename, "w") as f_sign:
                f_sign.write(signature_out)

            messagebox.showinfo("Sucesso", f"Assinatura gerada e salva em {filename} com sucesso!")

        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def verify_rsa_signature():
        try:
            # Fazem verificação de parametros e arquivos com a assinatura, arquivo a ser verificado e chave pública
            signature_file = filedialog.askopenfilename(title="Selecione o arquivo com a assinatura")
            if not signature_file:
                raise FileNotFoundError("Arquivo com a assinatura não foi selecionado.")
             
            file_to_verify = filedialog.askopenfilename(title="Selecione o arquivo a ser verificado")
            if not file_to_verify:
                raise FileNotFoundError("Arquivo a ser verificado não foi selecionado.")

            public_key_file = filedialog.askopenfilename(title="Selecione o arquivo com a chave pública (.pem):")
            if not public_key_file:
                raise FileNotFoundError("Arquivo com a chave pública não foi selecionado.")

            sha_version = simpledialog.askstring("Versão do SHA-2", "Escolha a versão do SHA-2 (256, 384, 512):")
            if sha_version not in ["256", "384", "512"]:
                raise ValueError("Versão inválida do SHA-2. Escolha entre 256, 384 ou 512.")

            output_format = simpledialog.askstring("Formato da Assinatura", "Formato da assinatura (Hex ou Base64):").upper()
            if output_format not in ["HEX", "BASE64"]:
                raise ValueError("Formato de assinatura inválido. Escolha entre Hex ou Base64.")

            with open(public_key_file, "rb") as f_pub:
                public_key = RSA.import_key(f_pub.read())

            with open(signature_file, "r") as f_sign:
                signature_encoded = f_sign.read()

            # Decodifica a assinatura
            signature = binascii.unhexlify(signature_encoded) if output_format == "HEX" else base64.b64decode(signature_encoded)

            with open(file_to_verify, "rb") as f_file:
                message = f_file.read()

            # Verifica a assinatura
            if sha_version == "256":
                h = SHA256.new(message)
            elif sha_version == "384":
                h = SHA384.new(message)
            elif sha_version == "512":
                h = SHA512.new(message)

            # Verifica a assinatura
            pkcs1_15.new(public_key).verify(h, signature)
            messagebox.showinfo("Sucesso", "A assinatura é válida!")

        except (ValueError, TypeError):
            messagebox.showerror("Erro", "A assinatura é inválida!")
        except Exception as e:
            messagebox.showerror("Erro", str(e))
            
    style = ttk.Style()

    label_title = ttk.Label(window, text="Assinatura RSA", anchor="center")
    label_title.pack(pady=20)

    style.configure("TButton", font=("Arial", 12), padding=10)
    style.configure("TLabel", font=("Arial", 16), padding=10)

    button_sign = ttk.Button(window, text="Assinar", command=sign_rsa, width=30)
    button_sign.pack(pady=10)

    button_verify = ttk.Button(window, text="Verificar Assinatura", command=verify_rsa_signature, width=30)
    button_verify.pack(pady=10)


    #window.mainloop()

# Chama o menu da assinatura
#rsa_sign_menu()
