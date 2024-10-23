import tkinter as tk
from tkinter import ttk
from Crypto.PublicKey import RSA

def keygen_menu():
    root = tk.Tk()
    root.title("Geração de Chaves")
    root.geometry("300x300")

    def exit_program():
        root.quit()

    def generate_keys():
        try:
            key_size = int(key_size_var.get())
            
            if key_size not in [1024, 2048]:
                raise ValueError("O tamanho da chave deve ser 1024 ou 2048 bits.")

            private_key = RSA.generate(key_size)
            private_key_pem = private_key.export_key()

            public_key = private_key.publickey()
            public_key_pem = public_key.export_key()

            with open("chave_privada.pem", "wb") as f_priv:
                f_priv.write(private_key_pem)

            with open("chave_publica.pem", "wb") as f_pub:
                f_pub.write(public_key_pem)

            tk.messagebox.showinfo("Sucesso", "Chaves geradas e salvas com sucesso!")

        except Exception as e:
            tk.messagebox.showerror("Erro", str(e))

    key_size_var = tk.StringVar(value="1024")

    style = ttk.Style()
    style.configure("TButton", font=("Arial", 12), padding=10)
    style.configure("TLabel", font=("Arial", 16), padding=10)

    label_title = ttk.Label(root, text="Geração de Chaves RSA", anchor="center")
    label_title.pack(pady=20)

    label_key_size = ttk.Label(root, text="Escolha o tamanho da chave:")
    label_key_size.pack(pady=10)

    radio_1024 = ttk.Radiobutton(root, text="1024 bits", variable=key_size_var, value="1024")
    radio_1024.pack(pady=5)
    
    radio_2048 = ttk.Radiobutton(root, text="2048 bits", variable=key_size_var, value="2048")
    radio_2048.pack(pady=5)

    button_generate = ttk.Button(root, text="Gerar Chaves", command=generate_keys)
    button_generate.pack(pady=20)

    button_exit = ttk.Button(root, text="Sair", command=exit_program)
    button_exit.pack(pady=10)

    root.mainloop()
