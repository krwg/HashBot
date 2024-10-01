#  _    _           _     ____        _   
# | |  | |         | |   |  _ \      | |  
# | |__| | __ _ ___| |__ | |_) | ___ | |_ 
# |  __  |/ _` / __| '_ \|  _ < / _ \| __|
# | |  | | (_| \__ \ | | | |_) | (_) | |_ 
# |_|  |_|\__,_|___/_| |_|____/ \___/ \__|
# 
import telebot
import hashlib
import json
import random
import requests
import os
from zxcvbn import zxcvbn
import logging

logging.basicConfig(level=logging.INFO)

bot = telebot.TeleBot("YOUR TOKEN")

@bot.message_handler(commands=['dev'])
def krwg(message):
	bot.send_message(message.chat.id, 'Автор бота: @krnwg Канал: @krwgpage') 

def check_password(password):
    response = requests.get(f"https://api.pwnedpasswords.com/range/{hashlib.sha1(password.encode()).hexdigest()[:5]}")
    if response.status_code == 200:
        for line in response.text.splitlines():
            if line.split(":")[0] == hashlib.sha1(password.encode()).hexdigest()[5:]:
                return True
    return False

def generate_codeword():
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return "".join(random.sample(characters, 10))

def load_user_history(user_id):
    try:
        with open(f'history_{user_id}.json', 'r') as f:
            history = json.load(f)
    except FileNotFoundError:
        history = {}
    return history

def save_user_history(user_id, history):
    with open(f'history_{user_id}.json', 'w') as f:
        json.dump(history, f)

user_codewords = {}

@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    if user_id not in user_codewords:
        bot.reply_to(message, f"Привет! Я бот для хеширования данных.\n"
                           f"Для начала работы вам необходимо установить кодовое слово. Используйте команду `/setcode <новое_кодовое_слово>`")
    else:
        bot.reply_to(message, f"Привет! Я бот для хеширования данных.\n"
                           f"Доступные команды:\n"
                           f"/hash - хешировать текст\n"
                           f"/history - показать историю хеширования\n"
                           f"/check - проверить пароль\n"
                           f"/generate - сгенерировать пароль\n"
                           f"/setcode - установить новое кодовое слово\n"
                           f"/help - помощь\n\n"
                           f"Пример: `/hash md5 Hello world`")

@bot.message_handler(commands=['help'])
def send_help(message):
    bot.reply_to(message, "Я могу хешировать текст с помощью алгоритмов MD5 и SHA-256.\n"
                       "Используйте команду `/hash` для хеширования.\n"
                       "Пример: `/hash md5 Hello world`")

@bot.message_handler(commands=['history'])
def show_history(message):
    user_id = message.from_user.id
    if user_id in user_codewords:
        codeword = user_codewords[user_id]
        bot.reply_to(message, "Введите кодовое слово:")
        bot.register_next_step_handler(message, lambda msg: process_codeword(msg, user_id, codeword))
    else:
        bot.reply_to(message, "У вас нет кодового слова. Используйте команду `/setcode` для его установки.")

def process_codeword(message, user_id, codeword):
    entered_codeword = message.text
    if entered_codeword == codeword:
        history = load_user_history(user_id)
        if history:
            response = "История хеширования:\n\n"
            for i, hash_info in enumerate(history.values()):
                response += f"{i+1}. Алгоритм: {hash_info['algorithm']}\n"
                response += f"  Хеш-сумма: {hash_info['hash']}\n"
            bot.reply_to(message, response)
        else:
            bot.reply_to(message, "История пуста.")
    else:
        bot.reply_to(message, "Неверное кодовое слово.")

@bot.message_handler(commands=['hash'])
def hash_text(message):
    user_id = message.from_user.id
    text = message.text.split()
    if len(text) < 3:
        bot.reply_to(message, "Недостаточно аргументов. Введите: `/hash <алгоритм> <текст>`")
        return

    hash_type = text[1].lower()
    text_to_hash = " ".join(text[2:])

    if hash_type in ["md5", "sha256"]:
        if hash_type == "md5":
            hash_value = hashlib.md5(text_to_hash.encode()).hexdigest()
        elif hash_type == "sha256":
            hash_value = hashlib.sha256(text_to_hash.encode()).hexdigest()

        history = load_user_history(user_id)
        history[len(history) + 1] = {"algorithm": hash_type, "hash": hash_value}
        save_user_history(user_id, history)

        bot.reply_to(message, f"Хеш-сумма ({hash_type}): {hash_value}")
    else:
        bot.reply_to(message, "Неверный алгоритм. Доступные: md5, sha256.")


@bot.message_handler(commands=['checkzxcvbn'])
def check_password(message):
    bot.send_message(message.chat.id, "Введите пароль для проверки. Он будет проверен программой zxcvbn - средство оценки надежности паролей, вдохновленное взломщиками паролей.")

    @bot.message_handler(func=lambda msg: msg.chat.id == message.chat.id and msg.text.strip())
    def handle_password(msg):
        password = msg.text.strip()
        score = zxcvbn(password)['score']

        if score <= 2:
            bot.send_message(msg.chat.id, "Ваш пароль слишком слабый. Попробуйте создать более сложный пароль.")
        elif score == 3:
            bot.send_message(msg.chat.id, "Ваш пароль средний. Попробуйте добавить дополнительные символы или слова.")
        else:
            bot.send_message(msg.chat.id, "Хороший пароль!")

@bot.message_handler(commands=['check'])
def check_password_handler(message):
    text = message.text.split()
    if len(text) < 2:
        bot.reply_to(message, "Введите пароль для проверки: `/check <пароль>`")
        return

    password = text[1]
    if check_password(password):
        bot.reply_to(message, "Этот пароль был найден в списке уязвимых паролей. Пожалуйста, используйте другой пароль.")
    else:
        bot.reply_to(message, "Этот пароль не найден в списке уязвимых паролей.")

@bot.message_handler(commands=['generate'])
def generate_password_handler(message):
    text = message.text.split()
    if len(text) < 2:
        bot.reply_to(message, "Введите длину пароля: `/generate <длина>`")
        return

    try:
        length = int(text[1])
    except ValueError:
        bot.reply_to(message, "Неверный формат длины пароля. Введите число.")
        return

    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    password = "".join(random.sample(characters, length))
    bot.reply_to(message, f"Сгенерированный пароль: {password}")

@bot.message_handler(commands=['setcode'])
def set_codeword(message):
    user_id = message.from_user.id
    text = message.text.split()
    if len(text) < 2:
        bot.reply_to(message, "Введите новое кодовое слово: `/setcode <новое_кодовое_слово>`")
        return

    new_codeword = text[1]
    user_codewords[user_id] = new_codeword
    bot.reply_to(message, "Кодовое слово успешно установлено.")

bot.polling()
#developer: krwg