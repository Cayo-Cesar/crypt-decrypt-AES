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
        # Função para cifrar a mensagem

        # 1. Solicitar a mensagem que o usuário deseja cifrar
        message = tkinter.simpledialog.askstring("Mensagem", "Digite a mensagem a ser cifrada:")
        if not message:
            tkinter.messagebox.showerror("Erro", "A mensagem não pode estar vazia.")
            return
        
        # 2. Solicitar o tamanho da chave
        key_size = tkinter.simpledialog.askinteger("Tamanho da Chave", "Digite o tamanho da chave (128, 192 ou 256 bits):")
        if key_size not in [128, 192, 256]:
            tkinter.messagebox.showerror("Erro", "O tamanho da chave deve ser 128, 192 ou 256 bits.")
            return

        # 3. Gerar a chave AES
        key = get_random_bytes(key_size // 8)  # Dividir o tamanho da chave por 8 para converter de bits para bytes
        
        # 4. Gerar o IV
        iv = get_random_bytes(16)  # O IV para AES tem 16 bytes (128 bits)
        
        # 5. Cifrar a mensagem
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = message.encode()  # Codifica a mensagem em bytes
        if len(padded_message) % 16 != 0:
            padded_message += b' ' * (16 - len(padded_message) % 16)  # Adiciona padding para ser múltiplo de 16
        ciphertext = cipher.encrypt(padded_message)
        
        # Diretório do programa (o mesmo onde o script está rodando)
        current_directory = os.getcwd()

        # 6. Salvar a mensagem cifrada, a chave e o IV em arquivos .txt no diretório do programa
        try:
            with open(os.path.join(current_directory, "mensagem_cifrada.txt"), "wb") as f_msg:
                f_msg.write(ciphertext)
            with open(os.path.join(current_directory, "chave_aes.txt"), "wb") as f_key:
                f_key.write(key)
            with open(os.path.join(current_directory, "iv.txt"), "wb") as f_iv:
                f_iv.write(iv)

            tkinter.messagebox.showinfo("Sucesso", "A mensagem foi cifrada e os arquivos foram salvos no diretório do programa!")
        except Exception as e:
            tkinter.messagebox.showerror("Erro", f"Erro ao salvar os arquivos: {str(e)}")

    def decrypt_aes():
        # Função para decifrar a mensagem

        try:
            # 1. Solicitar o arquivo com a mensagem cifrada
            file_ciphertext = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com a mensagem cifrada")
            if not file_ciphertext:
                tkinter.messagebox.showerror("Erro", "Arquivo com a mensagem cifrada não foi selecionado.")
                return
            
            # 2. Solicitar o arquivo com a chave AES
            file_key = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com a chave AES")
            if not file_key:
                tkinter.messagebox.showerror("Erro", "Arquivo com a chave AES não foi selecionado.")
                return

            # 3. Solicitar o arquivo com o IV
            file_iv = tkinter.filedialog.askopenfilename(title="Selecione o arquivo com o vetor IV")
            if not file_iv:
                tkinter.messagebox.showerror("Erro", "Arquivo com o IV não foi selecionado.")
                return

            # 4. Ler os arquivos
            with open(file_ciphertext, "rb") as f_msg:
                ciphertext = f_msg.read()

            with open(file_key, "rb") as f_key:
                key = f_key.read()

            with open(file_iv, "rb") as f_iv:
                iv = f_iv.read()

            # Verificar o tamanho da chave
            key_length = len(key)
            if key_length not in [16, 24, 32]:
                tkinter.messagebox.showerror("Erro", f"Tamanho da chave inválido: {key_length * 8} bits. Use chaves de 128, 192 ou 256 bits.")
                return

            # 5. Decifrar a mensagem
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_message = cipher.decrypt(ciphertext)

            # Remover o padding (espaços em branco)
            decrypted_message = decrypted_message.rstrip(b' ')

            # 6. Salvar a mensagem decifrada em um arquivo de texto
            current_directory = os.getcwd()
            decrypted_file_path = os.path.join(current_directory, "mensagem_decifrada.txt")

            with open(decrypted_file_path, "wb") as f_dec:
                f_dec.write(decrypted_message)

            tkinter.messagebox.showinfo("Sucesso", f"A mensagem foi decifrada e salva em '{decrypted_file_path}'.")

        except Exception as e:
            tkinter.messagebox.showerror("Erro", f"Erro ao decifrar a mensagem: {str(e)}")

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


