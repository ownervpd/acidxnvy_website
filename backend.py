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

# Wir initialisieren fernet hier, um Fehler früh zu fangen
fernet = None
if SECRET_KEY:
    try:
        fernet = Fernet(SECRET_KEY.encode())
    except Exception as e:
        print(f"FATALER FEHLER: SECRET_KEY ist ungültig! {e}")

app = Flask(__name__)
CORS(app)

# --- NEUE DEBUG-FUNKTION ---
@app.route('/debug-env')
def debug_env():
    # Diese Funktion zeigt uns, welche Werte auf Render wirklich ankommen.
    # Aus Sicherheitsgründen zeigen wir nur die ersten/letzten Zeichen des Tokens.
    env_vars = {
        "GUILD_ID_AUF_RENDER": GUILD_ID or "NICHT GEFUNDEN",
        "VERIFIED_ROLE_ID_AUF_RENDER": VERIFIED_ROLE_ID or "NICHT GEFUNDEN",
        "BOT_TOKEN_GELADEN": "Ja" if BOT_TOKEN else "Nein",
        "CLOUDFLARE_SECRET_KEY_GELADEN": "Ja" if CLOUDFLARE_SECRET_KEY else "Nein",
        "SECRET_KEY_GELADEN": "Ja" if SECRET_KEY else "Nein",
        "FERNET_INITIALISIERT": "Ja" if fernet else "Nein"
    }
    return jsonify(env_vars)
# --- ENDE DEBUG-FUNKTION ---

@app.route('/verify', methods=['POST'])
def verify_captcha():
    # Diese Funktion bleibt vorerst unverändert, da der Fehler vorher auftritt.
    # Wir müssen zuerst sicherstellen, dass die Konfiguration stimmt.
    data = request.json
    captcha_token = data.get('captchaToken')
    user_token = data.get('userToken')

    if not all([captcha_token, user_token, fernet]):
        return jsonify({'success': False, 'error': 'Server-Konfigurationsfehler'}), 500

    # 1. CAPTCHA bei Cloudflare verifizieren
    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload)
    if not verify_res.json().get('success'):
        return jsonify({'success': False, 'error': 'CAPTCHA fehlgeschlagen'}), 400

    # 2. User-Token entschlüsseln
    try:
        user_id = fernet.decrypt(user_token.encode()).decode()
    except Exception:
        return jsonify({'success': False, 'error': 'Ungültiger Verifizierungs-Token'}), 400

    # 3. Rollen ändern
    add_role_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}/roles/{VERIFIED_ROLE_ID}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    update_res = requests.put(add_role_url, headers=headers)

    if update_res.status_code == 204:
        return jsonify({'success': True})
    else:
        print(f"Discord API Fehler: {update_res.status_code} - {update_res.text}")
        return jsonify({'success': False, 'error': 'Rollen konnten nicht aktualisiert werden'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)