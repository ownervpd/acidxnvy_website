from flask import Flask, request, jsonify
from flask_cors import CORS # Stellt sicher, dass Flask-Cors importiert wird
import requests
import os
import json

# Lade die Konfiguration aus den Environment Variables auf Render
CLOUDFLARE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
UNVERIFIED_ROLE_ID = os.getenv("UNVERIFIED_ROLE_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")

app = Flask(__name__)

# --- KORREKTUR: CORS wird jetzt für die gesamte Anwendung aktiviert ---
# Das ist die robusteste Methode, um den "Blocked by CORS policy"-Fehler zu beheben.
CORS(app)
# --------------------------------------------------------------------

# Helfer-Funktionen, um die Token-Datei zu lesen/schreiben.
# Wichtig: Render löscht lokale Dateien bei jedem Deploy. Eine echte Datenbank wäre später besser.
def load_tokens():
    if os.path.exists('verification_tokens.json'):
        with open('verification_tokens.json', 'r') as f:
            try: return json.load(f)
            except json.JSONDecodeError: return {}
    return {}

def save_tokens(data):
    with open('verification_tokens.json', 'w') as f:
        json.dump(data, f, indent=4)

@app.route('/verify', methods=['POST'])
def verify_captcha():
    data = request.json
    captcha_token = data.get('captchaToken')
    user_token = data.get('userToken')

    if not all([captcha_token, user_token]):
        return jsonify({'success': False, 'error': 'Fehlende Daten'}), 400

    # 1. CAPTCHA bei Cloudflare verifizieren
    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload)
    verify_data = verify_res.json()

    if not verify_data.get('success'):
        # Gibt die Fehlercodes von Cloudflare für besseres Debugging zurück
        error_codes = verify_data.get('error-codes', [])
        return jsonify({'success': False, 'error': f'CAPTCHA-Verifizierung fehlgeschlagen: {error_codes}'}), 400

    # Temporäre Erfolgsantwort, da die Bot-Interaktion noch fehlt
    # Hier würde die Logik kommen, um die Rolle im Discord-Bot zu aktualisieren.
    print(f"CAPTCHA für user_token '{user_token}' erfolgreich verifiziert.")
    return jsonify({'success': True})


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)