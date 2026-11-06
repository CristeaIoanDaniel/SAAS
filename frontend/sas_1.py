
import customtkinter as ctk

# Configurare aplicatie
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Creare fereastra
app = ctk.CTk()
app.title("Prima mea aplicatie")
app.geometry("500x350")

# Titlu
titlu = ctk.CTkLabel(
    app,
    text="Bine ai venit!",
    font=("Arial", 25)
)
titlu.pack(pady=30)

# Buton
buton = ctk.CTkButton(
    app,
    text="Apasa aici",
    command=lambda: print("Salut!")
)
buton.pack(pady=20)

# Pornire aplicatie
app.mainloop()
