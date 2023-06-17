import tkinter as tk
import imaplib
import re
import os
import json
import string
import random
import requests
import traceback
from itertools import cycle
from capmonster_python import HCaptchaTask
from tkinter import messagebox
from colorama import Fore


with open('input/config.json') as f:
    cfg = json.load(f)

    captcha_key = cfg['Capmonster_key']

HOTMAILBOX_API_KEY = cfg['HOTMAILBOX_API_KEY']
SMS_ACTIVATE_API_KEY = cfg['SMS_ACTIVATE_API_KEY']
api_key = cfg['API_KEY']
__user_agent__ = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.47'
session = requests.Session()
mailcode = 'HOTMAIL'

service = 'ds'

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
        proxy_list = []
        with open('proxies.txt', 'r') as f:
            proxy_list = f.read().splitlines()
        return cycle(proxy_list)

    proxy = get_proxy()
    proxy_cycle = cycle(proxy)

    @staticmethod
    def get_proxies():
        proxy = next(utils.proxy_cycle)
        proxies = {"http": "http://" + proxy, "https": "http://" + proxy}
        return proxies

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

    response = session.get(link, headers=headers, proxy={'http': f'http://{proxy}', 'https': f'http://{proxy}'})
    token = str(response.text).split('token=')[1].split('">')[0]
    return token

class Misc:
    with open('input/config.json') as f:
        cfg = json.load(f)

        captcha_key = cfg['Capmonster_key']

    @staticmethod
    def solve_captcha():
        print("Solving captcha")
        capmonster = HCaptchaTask(Misc.captcha_key)
        task_id = capmonster.create_task("https://discord.com/register", "4c672d35-0701-42b2-88c3-78380b0db560")
        result = capmonster.join_task_result(task_id)
        captcha_token = result.get("gRecaptchaResponse")
        stats.solved += 1

        print(f"Captcha solved, token: {captcha_token}")
        return captcha_token

    @staticmethod
    def generate_email(num_accounts: int):
        HOTMAILBOX_API_KEY = 'your_api_key'
        mailcode = 'your_mailcode'
        buy_email_url = 'https://api.hotmailbox.me/mail/buy'
        params = {"apikey": HOTMAILBOX_API_KEY, "mailcode": mailcode, "quantity": num_accounts}
        email_password_pairs = []

        with requests.Session() as session:
            response = session.get(buy_email_url, params=params)

        if response.status_code == 200:
            response_json = response.json()
            if response_json["Code"] == 0:
                emails = response_json["Data"]["Emails"]

                for email_data in emails:
                    email = email_data["Email"]
                    password = email_data["Password"]
                    email_password_pairs.append((email, password))
                    print(f'Email: {email}, Password: {password}')

                    Misc.get_email_verification_code(email, password)

        return email_password_pairs

    @staticmethod
    def get_email_verification_code(email, password):
        # create an IMAP4 class with SSL
        mail = imaplib.IMAP4_SSL("imap-mail.outlook.com")
        # authenticate
        mail.login(email, password)

        # select the mailbox you want to delete in
        mailbox = "inbox"
        mail.select(mailbox)

        # get unread mails
        result, data = mail.uid('search', str, "(UNSEEN)")
        # if there is no unread mail, exit
        if result == 'OK':
            mail_ids = data[0]
            id_list = mail_ids.split()
            if not id_list:
                print('No unread emails.')
                return None
        else:
            print('Unable to search for mail.')
            return None

        # iterate through each email
        for num in id_list:
            result, data = mail.uid('fetch', num, '(BODY[TEXT])')
            if result != 'OK':
                print(f'Error: Unable to fetch email {num}.')
                continue

            raw_email = data[0][1]
            email_message = email.message_from_bytes(raw_email)

            # get the email body and search for a discord verification link
            if email_message.is_multipart():
                for payload in email_message.get_payload():
                    body = payload.get_payload(decode=True)
                    if body:
                        match = re.search(r'(https://discordapp\.com/verify/.+)', body.decode())
                        if match:
                            verifylink = match.group(1)
                            return verifylink
            else:
                body = email_message.get_payload(decode=True)
                if body:
                    match = re.search(r'(https://discordapp\.com/verify/.+)', body.decode())
                    if match:
                        verifylink = match.group(1)
                        return verifylink




    @staticmethod
    def get_number(api_key, service, retries=3, forward='', operator='', ref='', country=13,
                   phoneException='', maxPrice='', verification=''):

        if retries == 0:  # termination condition for recursion
            raise Exception("Maximum attempts exceeded")

        base_url = f"https://sms-activate.org/stubs/handler_api.php?api_key={api_key}&action=getNumberV2&service={service}&forward={forward}&operator={operator}&ref={ref}&country={country}&phoneException={phoneException}&maxPrice={maxPrice}&verification={verification}"

        print(f"URL: {base_url}")

        response = requests.get(base_url)

        if response.status_code == 200:
            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.text}")
            response_dict = json.loads(response.text)

            # response_content = '{"activationId":"1528260922","phoneNumber":"972543052669","activationCost":"10.00","countryCode":"13","canGetAnotherSms":true,"activationTime":"2023-06-16 02:30:52","activationOperator":"orange"}'
            # response_dict = json.loads(response_content)
            print(response_dict['phoneNumber'])
            # phone_number_details = Misc.get_number(api_key, service)

            if "phoneNumber" in response_dict:
                return response_dict
            else:
                print("Phone number not found in the response")
                if retries > 0:  # Retry the request if retries are still remaining
                    return Misc.get_number(api_key, service, retries - 1, forward, operator, ref,
                                           country, phoneException, maxPrice, verification)
                else:
                    raise Exception("Phone number not found and all retry attempts failed")

    @staticmethod
    def get_sms_verification_code(api_key):
        url = f"https://api.sms-activate.org/stubs/handler_api.php?api_key={api_key}&action=getActiveActivations"

        response = requests.get(url)

        if response.status_code == 200:
            if response.text.strip():  # this checks if the response is not empty
                response_json = json.loads(response.text)
                if response_json.get("status") == "success":
                    return response_json.get("activeActivations")
                else:
                    error_message = response_json.get("status")
                    if error_message == "BAD_KEY":
                        raise Exception("Invalid API Key")
                    elif error_message == "ERROR_SQL":
                        raise Exception("SQL Server Error")
                    elif error_message == "NO_ACTIVATIONS":
                        raise Exception("No Active Activations Found")
            else:
                raise Exception("Empty response received")
        else:
            raise Exception(f"Failed to get active activations, status code: {response.status_code}")

    @staticmethod
    def create_discord_account( email, phone_number, invite_code):
        try:
            os.system('cls')
            os.system(
                f'title BuG Discord Gen ^| Generated: {stats.genned} ^| Solved: {stats.solved} ^| Errors: {stats.errors}')

            proxy = next(utils.proxy_cycle)
            proxies = {"http": "http://" + proxy, "https": "http://" + proxy}

            usernames = open('input/usernames.txt', 'r').read().splitlines()
            user = random.choice(usernames)
            username = user + "".join(
                random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(2))
            password = "".join(random.choices(string.ascii_letters + string.digits, k=14))

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
                'X-Super-Properties': 'eyJvcyI6ICJXaW5kb3dzIiwgImJyb3dzZXIiOiAiQ2hyb21lIiwgImRldmljZSI6ICIiLCAiYnJvd3Nlcl91c2VyX2FnZW50IjogIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS81OC4wLjMwMjkuMTEwIFNhZmFyaS81MzcuMyIsICJicm93c2VyX3ZlcnNpb24iOiAiNTguMC4zMDI5LjExMCIsICJvc192ZXJzaW9uIjogIjEwIiwgInJlZmVycmVyIjogIiIsICJyZWZlcnJpbmdfZG9tYWluIjogIiIsICJyZWZlcnJlcl9jdXJyZW50IjogIiIsICJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiAiIiwgInJlbGVhc2VfY2hhbm5lbCI6ICJzdGFibGUiLCAiY2xpZW50X2J1aWxkX251bWJlciI6IDEwNTUzNiwgImNsaWVudF9ldmVudF9zb3VyY2UiOiBudWxsfQ==',
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

            response = requests.post('https://discord.com/api/v9/auth/register', headers=headers, json=payload,
                                     proxies=proxies)
            print(f"Account creation response: {response.text}")

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

        except Exception as e:
            print(f"Error during account creation: {traceback.format_exc()}")

        @staticmethod
        def emailVerify(proxy, cookies):
            # generate email and password
            email_password_pairs = Misc.generate_email(1)  # assuming you need 1 email account
            email, password = email_password_pairs[0]

            # get the verification link from the email
            verifyLink = Misc.get_email_verification_code(email, password)

            token = get_link(proxy, verifyLink)
            headers = {
                'authority': 'discord.com',
                'accept': '*/*',
                'accept-language': 'en-GB,en;q=0.9',
                'content-type': 'application/json',
                'cookie': f"__cfruid={cookies['__cfruid']};__dcfduid={cookies['__dcfduid']};__sdcfduid={cookies['__sdcfduid']};locale=en-GB",
                'origin': 'https://discord.com',
                'referer': 'https://discord.com/verify',
                'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
                'x-debug-options': 'bugReporterEnabled',
                'x-discord-locale': 'en-GB',
                'x-fingerprint': 'e0d7f355a88c417d80c95b610afb1c40',
                'x-super-properties': 'eyJvcyI6ICJXaW5kb3dzIiwgImJyb3dzZXIiOiAiQ2hyb21lIiwgImRldmljZSI6ICIiLCAiYnJvd3Nlcl91c2VyX2FnZW50IjogIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS81OC4wLjMwMjkuMTEwIFNhZmFyaS81MzcuMyIsICJicm93c2VyX3ZlcnNpb24iOiAiNTguMC4zMDI5LjExMCIsICJvc192ZXJzaW9uIjogIjEwIiwgInJlZmVycmVyIjogIiIsICJyZWZlcnJpbmdfZG9tYWluIjogIiIsICJyZWZlcnJlcl9jdXJyZW50IjogIiIsICJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiAiIiwgInJlbGVhc2VfY2hhbm5lbCI6ICJzdGFibGUiLCAiY2xpZW50X2J1aWxkX251bWJlciI6IDEwNTUzNiwgImNsaWVudF9ldmVudF9zb3VyY2UiOiBudWxsfQ==',
            }
            json = {
                'token': token,
                'captcha_key': None,
            }

            response = session.post('https://discord.com/api/v9/auth/verify', json=json, headers=headers,
                                    proxy={'http': f'http://{proxy}', 'https': f'http://{proxy}'})
            if 'token' in response.text:
                print(f"{Fore.BLUE}[ {Fore.GREEN}+ {Fore.BLUE}]{Fore.RESET} Email Verified Acccount")
                return response.json()['token']
            elif 'captcha_key' in response.text:
                print(f"{Fore.BLUE}[ {Fore.YELLOW}- {Fore.BLUE}]{Fore.RESET} Email Verify required captcha")
                captc_token = ""
                if captc_token == False:
                    print('Captcha failed')
                else:
                    json = {
                        'token': token,
                        'captcha_key': captc_token
                    }
                    response = session.post('https://discord.com/api/v9/auth/verify', json=json, headers=headers,
                                            proxy={'http': f'http://{proxy}', 'https': f'http://{proxy}'})
            else:
                return False

    @staticmethod
    def on_generate_account_click(num_accounts_entry, password_entry, invite_code_entry):
        try:
            num_accounts = int(num_accounts_entry.get())
            email_password_pairs = Misc.generate_email(num_accounts)
            if len(email_password_pairs) == num_accounts:
                for email, password in email_password_pairs:
                    print(f"Email: {email}, Password: {password}")

                    # Get phone number
                    phone_number = Misc.get_number(
                        api_key=SMS_ACTIVATE_API_KEY,
                        service=service
                    )
                    print(f"Phone Number: {phone_number}")

                    Misc.create_discord_account(email, phone_number, invite_code_entry.get(), password_entry.get())

                    # Email verification
                    proxy = next(utils.proxy_cycle)
                    cookies = {
                        "__cfruid": "",
                        "__dcfduid": "",
                        "__sdcfduid": "",
                        "locale": "en-GB"
                    }
                    Misc.emailVerify(proxy, cookies)

                    # Update stats
                    stats.genned += 1
                    stats.solved += 1
                    update_stats_label()
            else:
                # Handle the case when the number of email_password_pairs does not match the requested num_accounts
                stats.errors += num_accounts - len(email_password_pairs)

            messagebox.showinfo("Success", f"{num_accounts} accounts created successfully")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            print(f"Error during account generation: {traceback.format_exc()}")


root.title("BuG Discord Account Generator")
root.geometry("300x250")

num_accounts_label = tk.Label(root, text="Number of accounts")
num_accounts_label.pack()
num_accounts_entry = tk.Entry(root)
num_accounts_entry.pack()

password_label = tk.Label(root, text="Password")
password_label.pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

invite_code_label = tk.Label(root, text="Invite Code")
invite_code_label.pack()
invite_code_entry = tk.Entry(root)
invite_code_entry.pack()

stats_label = tk.Label(root, text="")
stats_label.pack()

generate_account_button = tk.Button(root, text="Generate Account",
                                    command=lambda: Misc.on_generate_account_click(num_accounts_entry, password_entry,
                                                                                   invite_code_entry))
generate_account_button.pack()

update_stats_label()

root.mainloop()
