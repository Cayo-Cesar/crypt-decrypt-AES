import tkinter
from tkinter import ttk
import tkinter.messagebox
import tkinter.filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import base64
import binascii

#Função Principal, que chama as funções de criptografia e descriptografia
def aes_menu():
    window = tkinter.Tk()
    window.title("AES")
    window.geometry("300x300")

    #Função de criptografia
    def encrypt_aes():
        try:
            #Pede a mensagem a ser cifrada
            message = tkinter.simpledialog.askstring("Mensagem", "Digite a mensagem a ser cifrada:")
            if not message:
                raise ValueError("A mensagem não pode estar vazia.")

            #Pede o tamanho da chave
            key_size = tkinter.simpledialog.askinteger("Tamanho da Chave", "Digite o tamanho da chave (128, 192 ou 256 bits):")
            if key_size not in [128, 192, 256]:
                raise ValueError("O tamanho da chave deve ser 128, 192 ou 256 bits.")
            
            #Pede o modo de operação
            mode_choice = tkinter.simpledialog.askstring("Modo de Operação", "Escolha o modo de operação (CBC ou ECB):").upper()
            if mode_choice not in ["CBC", "ECB"]:
                raise ValueError("Modo de operação inválido. Escolha entre CBC ou ECB.")
            
            #Pede o formato de saída
            output_format = tkinter.simpledialog.askstring("Formato de Saída", "Escolha o formato de saída (Hex ou Base64):").upper()
            if output_format not in ["HEX", "BASE64"]:
                raise ValueError("Formato de saída inválido. Escolha entre Hex ou Base64.")

            #Gera a chave e o vetor IV
            key = get_random_bytes(key_size // 8)
            
            iv = None
            #Se o modo de operação for CBC, gera um vetor IV
            if mode_choice == "CBC":
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
            else:
                cipher = AES.new(key, AES.MODE_ECB)

            #Preenche a mensagem com espaços para que ela tenha um tamanho múltiplo de 16
            padded_message = message.encode()
            if len(padded_message) % 16 != 0:
                padded_message += b' ' * (16 - len(padded_message) % 16)
            ciphertext = cipher.encrypt(padded_message)

            #Salva os arquivos com a mensagem cifrada, a chave e o vetor IV
            current_directory = os.getcwd()

            #Converte os bytes para Hex ou Base64
            if output_format == "HEX":
                ciphertext_out = binascii.hexlify(ciphertext).decode()
                key_out = binascii.hexlify(key).decode()
                if iv:
                    iv_out = binascii.hexlify(iv).decode()
            else:
                ciphertext_out = base64.b64encode(ciphertext).decode()
                key_out = base64.b64encode(key).decode()
                if iv:
                    iv_out = base64.b64encode(iv).decode()

            #Salva os arquivos
            with open(os.path.join(current_directory, "mensagem_cifrada.txt"), "w") as f_msg:
                f_msg.write(ciphertext_out)
            with open(os.path.join(current_directory, "chave_aes.txt"), "w") as f_key:
                f_key.write(key_out)
            
            #Se o modo de operação for CBC, salva o vetor IV
            if mode_choice == "CBC" and iv is not None:
                with open(os.path.join(current_directory, "iv.txt"), "w") as f_iv:
                    f_iv.write(iv_out)

            tkinter.messagebox.showinfo("Sucesso", "A mensagem foi cifrada e os arquivos foram salvos no diretório do programa!")

        except Exception as e:
            tkinter.messagebox.showerror("Erro", str(e))

    #Função de descriptografia
    def decrypt_aes():
        try:
            #Pede os arquivos com a mensagem cifrada, a chave e o vetor IV
            file_ciphertext = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com a mensagem cifrada")
            if not file_ciphertext:
                raise FileNotFoundError("Arquivo com a mensagem cifrada não foi selecionado.")

            #Pede o arquivo com a chave AES
            file_key = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com a chave AES")
            if not file_key:
                raise FileNotFoundError("Arquivo com a chave AES não foi selecionado.")

            #Pede o modo de operação
            mode_choice = tkinter.simpledialog.askstring("Modo de Operação", "Escolha o modo de operação (CBC ou ECB):").upper()
            if mode_choice not in ["CBC", "ECB"]:
                raise ValueError("Modo de operação inválido. Escolha entre CBC ou ECB.")

            #Pede o formato de entrada
            input_format = tkinter.simpledialog.askstring("Formato de Entrada", "Escolha o formato de entrada (Hex ou Base64):").upper()
            if input_format not in ["HEX", "BASE64"]:
                raise ValueError("Formato de entrada inválido. Escolha entre Hex ou Base64.")

            #Lê os arquivos com a mensagem cifrada e a chave
            with open(file_ciphertext, "r") as f_msg:
                ciphertext = f_msg.read()
            with open(file_key, "r") as f_key:
                key = f_key.read()

            #Converte os bytes para Hex ou Base64
            if input_format == "HEX":
                ciphertext = binascii.unhexlify(ciphertext)
                key = binascii.unhexlify(key)
            else:
                ciphertext = base64.b64decode(ciphertext)
                key = base64.b64decode(key)

            #Verifica o tamanho da chave
            key_length = len(key)
            if key_length not in [16, 24, 32]:
                raise ValueError(f"Tamanho da chave inválido: {key_length * 8} bits. Use chaves de 128, 192 ou 256 bits.")

            #Se o modo de operação for CBC, pede o arquivo com o vetor IV
            iv = None
            if mode_choice == "CBC":
                file_iv = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com o vetor IV")
                if not file_iv:
                    raise FileNotFoundError("Arquivo com o IV não foi selecionado.")
                with open(file_iv, "r") as f_iv:
                    iv = f_iv.read()
                if input_format == "HEX":
                    iv = binascii.unhexlify(iv)
                else:
                    iv = base64.b64decode(iv)

            #Cria o objeto AES
            if mode_choice == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
            else:
                cipher = AES.new(key, AES.MODE_ECB)

            #Descriptografa a mensagem
            decrypted_message = cipher.decrypt(ciphertext)
            decrypted_message = decrypted_message.rstrip(b' ')

            #Salva a mensagem descriptografada
            current_directory = os.getcwd()
            decrypted_file_path = os.path.join(current_directory, "mensagem_decifrada.txt")

            with open(decrypted_file_path, "wb") as f_dec:
                f_dec.write(decrypted_message)

            tkinter.messagebox.showinfo("Sucesso", f"A mensagem foi decifrada e salva em '{decrypted_file_path}'.")

        except Exception as e:
            tkinter.messagebox.showerror("Erro", str(e))

    #Configurações da Interface Gráfica   
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