import tkinter as tk
import os
import json
import string
import random
import requests
import threading
import time
import ctypes
from itertools import cycle
from capmonster_python import HCaptchaTask
from pyOutlook import OutlookAccount
from tkinter import messagebox
import uuid

HOTMAILBOX_API_KEY = "your_hotmailbox_api_key"
SMS_ACTIVATE_API_KEY = "your_sms_activate_api_key"

__user_agent__ = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.47'
session = requests.Session()

dcfduid_value = str(uuid.uuid4())
sdcfduid_value = str(uuid.uuid4())

root = tk.Tk()

class stats:
    genned = 0
    errors = 0
    solved = 0

stats_label = tk.Label(root, text="")
stats_label.pack()

def update_stats_label():
    stats_label.config(text=f"Generated: {stats.genned} | Solved: {stats.solved} | Errors: {stats.errors}")

class utils:
    @staticmethod
    def get_proxy():
        with open('input/proxies.txt', 'r') as f:
            proxies = [line.strip('\n') for line in f]
            return proxies


proxy = utils.get_proxy()
proxy_cycle = cycle(proxy)

def get_link(proxy: str, verifyLink: str) -> str:
    link = str(verifyLink).split('\r')[0]
    headers = {
        'authority': 'click.discord.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-GB,en;q=0.9',
        'sec-ch-ua': '"Chromium";v="108", "Not A(Brand";v="24", "Google Chrome";v="108"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': __user_agent__,
    }

class Misc:
    with open('input/config.json') as f:
        cfg = json.load(f)

        captcha_key = cfg['Capmonster_key']

    @staticmethod
    def solve_captcha():
        capmonster = HCaptchaTask(Misc.captcha_key)
        task_id = capmonster.create_task("https://discord.com/register", "4c672d35-0701-42b2-88c3-78380b0db560")
        result = capmonster.join_task_result(task_id)
        captcha_token = result.get("gRecaptchaResponse")
        stats.solved += 1
        return captcha_token

    @staticmethod
    def generate_email():
        response = requests.get(f"https://api.hotmailbox.me/v1/email/create?apikey={HOTMAILBOX_API_KEY}")
        if response.status_code == 200:
            return response.json()["email"]
        else:
            raise Exception("Failed to generate email")

    @staticmethod
    def get_email_verification_code(email):
        outlook_account = OutlookAccount(email)
        messages = outlook_account.get_messages()
        for message in messages:
            if "Discord" in message.subject:
                return message.body.split(" ")[-1].strip()
        raise Exception("Email verification code not found")

    @staticmethod
    def buy_phone_number():
        response = requests.get(
            f"http://sms-activate.ru/stubs/handler_api.php?api_key={SMS_ACTIVATE_API_KEY}&action=getNumber&service=di")
        if response.status_code == 200 and "ACCESS_NUMBER" in response.text:
            return response.text.split(":")[2]
        else:
            raise Exception("Failed to buy phone number")

    @staticmethod
    def get_sms_verification_code(phone_number):
        response = requests.get(
            f"http://sms-activate.ru/stubs/handler_api.php?api_key={SMS_ACTIVATE_API_KEY}&action=getStatus&id={phone_number}")
        if response.status_code == 200 and "STATUS_OK" in response.text:
            return response.text.split(":")[1]
        else:
            raise Exception("SMS verification code not found")

    @staticmethod
    def create_discord_account(username, password, email, phone_number, invite_code):
        os.system('cls')
        os.system(
            f'title BuG Discord Gen ^| Generated: {stats.genned} ^| Solved: {stats.solved} ^| Errors: {stats.errors}')

        proxy = next(utils.proxy_cycle)
        proxies = {"http": "http://" + proxy, "https": "http://" + proxy}


        usernames = open('input/usernames.txt', 'r').read().splitlines()
        user = random.choice(usernames)
        username = user + "".join(
            random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(2))

        captcha_token = Misc.solve_captcha()
        invite_code = invite_code_entry.get()
        xsup = 'ewogICAgIm9zIjogIldpbmRvd3MiLAogICAgImJyb3dzZXIiOiAiQ2hyb21lIiwKICAgICJkZXZpY2UiOiAiIiwKICAgICJzeXN0ZW1fbG9jYWxlIjogImVuLVVTIiwKICAgICJicm93c2VyX3VzZXJfYWdlbnQiOiAiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzU4LjAuMzAyOS4xMTAgU2FmYXJpLzUzNy4zIiwKICAgICJicm93c2VyX3ZlcnNpb24iOiAiNTguMC4zMDI5LjExMCIsCiAgICAib3NfdmVyc2lvbiI6ICIxMCIsCiAgICAicmVmZXJyZXIiOiAiIiwKICAgICJyZWZlcnJpbmdfZG9tYWluIjogIiIsCiAgICAicmVmZXJyZXJfY3VycmVudCI6ICIiLAogICAgInJlZmVycmluZ19kb21haW5fY3VycmVudCI6ICIiLAogICAgInJlbGVhc2VfY2hhbm5lbCI6ICJzdGFibGUiLAogICAgImNsaWVudF9idWlsZF9udW1iZXIiOiA1MzE2OCwKICAgICJjbGllbnRfZXZlbnRfc291cmNlIjogbnVsbAp9'

        payload = {
            "captcha_service": "hcaptcha",
            "captcha_key": captcha_token,
            "consent": "true",
            "date_of_birth": "2000-02-13",
            "email": email,
            "gift_code_sku_id": "null",
            "invite": invite_code,
            "password": password,
            "promotional_email_opt_in": "false",
            "username": username
        }

        headers = {
            'Host': 'discord.com',
            'Connection': 'keep-alive',
            'X-Super-Properties': xsup,
            'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
            'Accept-Language': 'en-US',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.47',
            'Content-Type': 'application/json',
            'Authorization': 'undefined',
            'Accept': '*/*',
            'Origin': 'https://discord.com',
            'Referer': 'https://discord.com/register',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'X-Debug-Options': 'bugReporterEnabled',
            'Accept-Encoding': 'gzip, deflate, br',
            "Cookie": f"__dcfduid=79e1bb00095911eea719b93af5a92cca; __sdcfduid=79e1bb01095911eea719b93af5a92ccab1ec32c421d76b4ad411823bec932a8b74416371281cb47ea0b31707c0ab878e; _gcl_au=1.1.33345081.1647643031; _ga=GA1.2.291092015.1647643031; _gid=GA1.2.222777380.1647643031; OptanonConsent=isIABGlobal=false&datestamp=Fri+Mar+18+2022+18%3A53%3A43+GMT-0400+(%E5%8C%97%E7%BE%8E%E4%B8%9C%E9%83%A8%E5%A4%8F%E4%BB%A4%E6%97%B6%E9%97%B4)&version=6.17.0&hosts=&consentId=3a8b1293-1b4a-4f6d-9253-1da18f8c265b&interactionCount=1&landingPath=NotLandingPage&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1%2CC0004%3A1&geolocation=CN%3B&AwaitingReconsent=false"
        }

        response = requests.post('https://discord.com/api/v9/auth/register', headers=headers, json=payload,proxies=proxies)

        if 'captcha-required' in response.text:
            print(f"Captcha required")
            stats.errors += 1
        elif 'You are being rate limited.' in response.text:
            print(f"Rate limited")
            stats.errors += 1
        elif 'captcha_key: Invalid captcha verification code' in response.text:
            print(f"Invalid captcha")
            stats.errors += 1
        else:
            print(f"Account created successfully")
            with open('output/hits.txt', 'a') as f:
                f.write(f'{email}:{password}\n')
            f.close()
            stats.genned += 1
            stats.solved += 1

        update_stats_label()


    def on_generate_account_click(username_entry, password_entry, invite_code_entry):
        try:
            email = Misc.generate_email()
            phone_number = Misc.buy_phone_number()
            username = username_entry.get()
            password = password_entry.get()
            invite_code = invite_code_entry.get()
            Misc.create_discord_account(username, password, email, phone_number, invite_code)
            messagebox.showinfo("Success", "Account created successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))


root.title("BuG Discord Account Generator")
root.geometry("300x150")
username_label = tk.Label(root, text="Username")
username_label.pack()
username_entry = tk.Entry(root)
username_entry.pack()
password_label = tk.Label(root, text="Password")
password_label.pack()
password_entry = tk.Entry(root)
password_entry.pack()
invite_code_label = tk.Label(root, text="Invite Code")
invite_code_label.pack()
invite_code_entry = tk.Entry(root)
invite_code_entry.pack()
generate_account_button = tk.Button(root, text="Generate Account",
                                    command=lambda: Misc.on_generate_account_click(username_entry, password_entry,
                                                                                   invite_code_entry))
generate_account_button.pack()
root.mainloop()
