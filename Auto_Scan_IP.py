import tkinter as tk
from tkinter import scrolledtext, simpledialog
import configparser
import json
import time
from threading import Thread
import requests
import logging
from functools import lru_cache
import gettext
import os
import re

# Initialize gettext
locale_path = os.path.join(os.path.dirname(__file__), 'locale')
gettext.bindtextdomain('ip_scanner', locale_path)
gettext.textdomain('ip_scanner')
_ = gettext.gettext

# Configure logging
logging.basicConfig(filename='ip_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config.read('config.ini')

API_KEY = config['API']['VIRUSTOTAL_API_KEY']

# Create a logger
logger = logging.getLogger(__name__)

@lru_cache(maxsize=128)  # Cache up to 128 API responses
def scan_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
      "x-apikey": API_KEY
    }
    try:
      print(f"Sending request to: {url}")
      print(f"Headers: {headers}")
      response = requests.get(url, headers=headers, verify=True)
      print(f"Response status code: {response.status_code}")  # Added for debugging

      # Log the entire response for detailed error analysis
      logger.debug(f"Response text: {response.text}") 

      response.raise_for_status()  # Raise an error for 4xx or 5xx status codes
      return response.json()
    except requests.exceptions.HTTPError as http_err:
      error_message = f"HTTP error occurred: {http_err}"
      logger.error(error_message)
      return {"error": error_message}
    except requests.exceptions.RequestException as req_err:
      error_message = f"Request exception occurred: {req_err}"
      logger.error(error_message)
      return {"error": error_message}
    except Exception as e:
      error_message = f"Unhandled error occurred: {e}"
      logger.error(error_message)
      return {"error": error_message}

def update_text(text_widget, text):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, text + '\n')
    text_widget.config(state=tk.DISABLED)
    text_widget.see(tk.END)

def extract_ip_from_clipboard():
    clipboard_contents = tk.Tk().clipboard_get()
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'  # Pattern for IPv4 address
    match = re.search(ip_pattern, clipboard_contents)
    if match:
        return match.group()
    else:
        return None

def configure_api_key():
    new_api_key = simpledialog.askstring(_("Configure API Key"), _("Enter new API key:"))
    if new_api_key:
        config['API']['VIRUSTOTAL_API_KEY'] = new_api_key
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        global API_KEY
        API_KEY = new_api_key

def set_scan_interval():
    new_interval = simpledialog.askinteger(_("Set Scan Interval"), _("Enter new scan interval (seconds):"))
    if new_interval:
        global SCAN_INTERVAL
        SCAN_INTERVAL = new_interval

def main(text_widget):
    last_ip = ""
    while True:
        clipboard_ip = extract_ip_from_clipboard()
        if clipboard_ip and clipboard_ip != last_ip:
            try:
                result = scan_ip(clipboard_ip)
                if "error" in result:
                    update_text(text_widget, f"Error: {result['error']}")
                else:
                    # Filter the result to only show relevant information
                    filtered_result = {
                        "IP": result.get("data", {}).get("id"),
                        "Last Analysis Stats": result.get("data", {}).get("attributes", {}).get("last_analysis_stats")
                        # Add more fields as needed (e.g., geolocation, domain information)
                    }
                    update_text(text_widget, json.dumps(filtered_result, indent=4))
            except Exception as e:
                update_text(text_widget, f"Unhandled error occurred: {e}")
                logger.error(f"Unhandled error occurred: {e}")
            last_ip = clipboard_ip
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    root = tk.Tk()
    root.title(_("IP Scanner"))
    root.geometry("500x500")

    text = scrolledtext.ScrolledText(root, bg='black', fg='light green', font=("Cascadia Code", 10))
    text.pack(fill=tk.BOTH, expand=True)

    # Menu Bar
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)

    # File menu
    file_menu = tk.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label=_("Exit"), command=root.quit)
    menu_bar.add_cascade(label=_("File"), menu=file_menu)

    # Options menu
    options_menu = tk.Menu(menu_bar, tearoff=0)
    options_menu.add_command(label=_("Configure API Key"), command=configure_api_key)
    options_menu.add_command(label=_("Set Scan Interval"), command=set_scan_interval)
    menu_bar.add_cascade(label=_("Options"), menu=options_menu)

    # Start scanning in a separate thread
    SCAN_INTERVAL = 1  # Default scan interval in seconds
    thread = Thread(target=main, args=(text,))
    thread.start()

    root.mainloop()
