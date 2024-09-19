import telebot
import requests
import re
import os
import time
import tempfile

# Telegram bot API va VirusTotal API kalitlari
TELEGRAM_BOT_TOKEN = '****************************************'
VIRUSTOTAL_API_KEY = '**************************************************'

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Fayl yuklanganda qaytarilgan Scan ID ni saqlash uchun lug'at
file_scan_ids = {}

# URL'larni tekshirish uchun regex
url_regex = re.compile(
    r'(?:(?:https?|ftp):\/\/)?'  # protokol (ixtiyoriy)
    r'(?:\S+(?::\S*)?@)?'  # foydalanuvchi va parol (ixtiyoriy)
    r'(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])'  # IPv4 boshlang'ich qismi
    r'(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}'  # IPv4 o'rta qismi
    r'(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))|'  # IPv4 oxirgi qismi
    r'(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)'  # domen nomlari
    r'(?:\.(?:[a-z\u00a1-\uffff]{2,}))'  # yuqori darajadagi domen
    r'|localhost)'  # localhost manzili
    r'(?::\d{2,5})?'  # port raqami (ixtiyoriy)
    r'(?:[/?#]\S*)?',  # query, fragment va boshqa elementlar (ixtiyoriy)
    re.IGNORECASE)

# VirusTotal orqali URL xavfsizligini tekshirish funksiyasi
def check_url_virustotal(url):
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    
    response = requests.get(vt_url, params=params)
    result = response.json()

    if result['response_code'] == 1:
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        return f"Link {positives}/{total} antivirus dasturi tomonidan xavfli deb topilgan."
    else:
        return "Bu URL VirusTotal bazasida topilmadi."

# VirusTotal orqali fayl xavfsizligini tekshirish funksiyasi
def check_file_virustotal(file_path, message_id):
    vt_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    params = {'apikey': VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.post(vt_url, files=files, params=params)
        result = response.json()
        if 'scan_id' in result:
            scan_id = result['scan_id']
            file_scan_ids[message_id] = scan_id  # Scan ID ni saqlaymiz
            bot.reply_to(current_message, f"Fayl VirusTotal'da tekshirildi. Scan ID: {scan_id}. Tahlil qilish uchun biroz kuting va '/get_report {scan_id}' buyrug'ini yuboring.")
        else:
            return "VirusTotal'da faylni tekshirishda xatolik yuz berdi."
    except Exception as e:
        return f"Faylni VirusTotal'ga yuborishda xatolik yuz berdi: {str(e)}"

# VirusTotal'da fayl hisobotini olish funksiyasi
def get_file_report(scan_id):
    vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
    
    try:
        response = requests.get(vt_url, params=params)
        result = response.json()
        if result['response_code'] == 1:
            positives = result.get('positives', 0)
            total = result.get('total', 0)
            return f"Fayl tahlili natijasi: {positives}/{total} antivirus dasturlari xavfli deb topdi."
        else:
            return "Fayl tahlili natijasi topilmadi. Biroz vaqt kutib qayta urinib ko'ring."
    except Exception as e:
        return f"Fayl tahlil natijasini olishda xatolik yuz berdi: {str(e)}"

# Botga keladigan xabarlarga javob berish
@bot.message_handler(commands=['start'])
def send_welcome(message):
    global current_message
    current_message = message
    bot.reply_to(message, "Assalomu alaykum! Bu bot orqali fayllar va URL'larning xavfsizligini tekshirish mumkin. Faqat fayl yoki URL yuboring.")

# URL'larni aniqlash va tekshirish
@bot.message_handler(func=lambda message: True)
def handle_message(message):
    urls = re.findall(url_regex, message.text)
    
    if urls:
        for url in urls:
            # Agar foydalanuvchi http yoki https yozmagan bo'lsa, qo'shib beramiz
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            result = check_url_virustotal(url)
            bot.reply_to(message, f"Natija uchun: {url}\n{result}")
    else:
        bot.reply_to(message, "Iltimos, to'g'ri URL yoki IP manzil yuboring.")

# Fayllarni qabul qilish va tekshirish
@bot.message_handler(content_types=['document'])
def handle_docs(message):
    global current_message
    current_message = message
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        # Faylni vaqtinchalik papkaga saqlash
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(downloaded_file)
            temp_file_path = temp_file.name

        # Fayl VirusTotal'da tekshirildi
        check_file_virustotal(temp_file_path, message.message_id)

        # Faylni tekshirgandan keyin o'chirish
        os.remove(temp_file_path)

    except Exception as e:
        bot.reply_to(message, f"Faylni tekshirishda xatolik yuz berdi: {str(e)}")

# Fayl hisobotini so'rash komandasi
@bot.message_handler(commands=['get_report'])
def handle_get_report(message):
    try:
        scan_id = message.text.split()[1]  # '/get_report SCAN_ID' formatida bo'lishi kerak
        result = get_file_report(scan_id)
        bot.reply_to(message, result)
    except IndexError:
        bot.reply_to(message, "Iltimos, Scan ID ni kiritganingizga ishonch hosil qiling. Format: /get_report SCAN_ID")

# Botni ishga tushirish
bot.polling()
