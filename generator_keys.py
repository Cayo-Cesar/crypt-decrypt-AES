import tkinter as tk
from tkinter import ttk

def keygen_menu():
    root = tk.Tk()
    root.title("Geração de Chaves")
    root.geometry("300x300")

    def exit_program():
        root.quit()

    def generate_keys():
        pass

    style = ttk.Style()

    style.configure("TButton", font=("Arial", 12), padding=10)
    style.configure("TLabel", font=("Arial", 16), padding=10)

    return