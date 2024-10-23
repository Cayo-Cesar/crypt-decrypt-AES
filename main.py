import tkinter as tk
from tkinter import ttk
from encrypt_decrypt import aes_menu

def main_menu():
    root = tk.Tk()
    root.title("Sistema de Criptografia")
    root.geometry("400x400")

    style = ttk.Style()

    style.configure("TButton", font=("Arial", 12), padding=10)
    style.configure("TLabel", font=("Arial", 16), padding=10)

    def exit_program():
        root.quit()

    def open_aes_menu():
        aes_menu()
        return

    def open_rsa_keygen_menu():
        return

    def open_rsa_operations_menu():
        return

    label = ttk.Label(root, text="Menu Principal", style="TLabel")
    label.pack(pady=20)

    button_aes = ttk.Button(root, text="Cifragem/Decifragem AES", command=open_aes_menu, width=30)
    button_aes.pack(pady=10)

    button_rsa_keygen = ttk.Button(root, text="Geração de Chaves", command=open_rsa_keygen_menu, width=30)
    button_rsa_keygen.pack(pady=10)

    button_rsa_operations = ttk.Button(root, text="Assinatura/Verificação RSA", command=open_rsa_operations_menu, width=30)
    button_rsa_operations.pack(pady=10)

    button_exit = ttk.Button(root, text="Sair", command=exit_program, width=30)
    button_exit.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main_menu()