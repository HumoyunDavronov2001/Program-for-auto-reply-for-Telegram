import telebot
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

# Bot tokenini BotFather orqali olganingizdan so'ng pastdagi joyga joylashtiring
BOT_TOKEN = '7506906334:AAFoFbZxf8qfKiUD2m8NFvWQPpZICHSNQNM'
bot = telebot.TeleBot(BOT_TOKEN)

# Aniq foydalanuvchi ID'si
TARGET_USER_ID = 2033619874  # Maqsadli foydalanuvchi ID'si

# Tkinter oynasini yaratish
window = tk.Tk()
window.title("Telegram Bot")
window.geometry("400x300")

# Xabar yozish uchun matn maydoni
label_message = tk.Label(window, text="Yuboriladigan matnni kiriting:")
label_message.pack(pady=10)
text_message = tk.Entry(window, width=50)
text_message.pack()

# Fayl yo'lini tanlash uchun maydon
file_path = ""

def browse_file():
    global file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        label_file.config(text=f"Tanlangan fayl: {file_path.split('/')[-1]}")
    else:
        label_file.config(text="Fayl tanlanmagan")

# Fayl tanlash tugmasi va fayl yo'li ko'rsatiladigan maydon
button_browse = tk.Button(window, text="Fayl tanlash", command=browse_file)
button_browse.pack(pady=10)
label_file = tk.Label(window, text="Fayl tanlanmagan")
label_file.pack(pady=10)

# Xabar yoki faylni yuborish funksiyasi
def send_message_or_file():
    try:
        if text_message.get():
            # Foydalanuvchiga matnli xabar yuborish
            bot.send_message(TARGET_USER_ID, text_message.get())
            messagebox.showinfo("Muvaffaqiyat", "Matnli xabar yuborildi!")
            text_message.delete(0, tk.END)  # Matn maydonini tozalash
        elif file_path:
            # Foydalanuvchiga fayl yuborish
            with open(file_path, 'rb') as file:
                bot.send_document(TARGET_USER_ID, file)
            messagebox.showinfo("Muvaffaqiyat", "Fayl yuborildi!")
        else:
            messagebox.showerror("Xato", "Xabar yoki faylni kiriting!")
    except Exception as e:
        messagebox.showerror("Xato", f"Xato yuz berdi: {str(e)}")

# Yuborish tugmasi
button_send = tk.Button(window, text="Yuborish", command=send_message_or_file)
button_send.pack(pady=20)

# Dasturni ishga tushirish
window.mainloop()
