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
UNVERIFIED_ROLE_ID = os.getenv("UNVERIFIED_ROLE_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")
SECRET_KEY = os.getenv("SECRET_KEY") # Der geheime Schlüssel zur Entschlüsselung

# Prüfe, ob alle notwendigen Schlüssel vorhanden sind
if not all([CLOUDFLARE_SECRET_KEY, BOT_TOKEN, GUILD_ID, UNVERIFIED_ROLE_ID, VERIFIED_ROLE_ID, SECRET_KEY]):
    raise ValueError("Eine oder mehrere notwendige Environment Variables fehlen!")

# Initialisiere das Entschlüsselungs-Tool
fernet = Fernet(SECRET_KEY.encode())
app = Flask(__name__)
CORS(app) # Erlaube Anfragen von überall, um CORS-Probleme final auszuschließen

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
        error_codes = verify_data.get('error-codes', [])
        return jsonify({'success': False, 'error': f'CAPTCHA-Verifizierung fehlgeschlagen: {error_codes}'}), 400

    # 2. User-Token entschlüsseln, um die echte User-ID zu erhalten
    try:
        decrypted_user_id_bytes = fernet.decrypt(user_token.encode())
        user_id = decrypted_user_id_bytes.decode()
    except Exception as e:
        print(f"Token Entschlüsselungs-Fehler: {e}")
        return jsonify({'success': False, 'error': 'Ungültiger oder abgelaufener Verifizierungs-Token'}), 400

    # 3. Rollen des Users auf Discord ändern
    discord_api_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    
    # Payload, der die unverifizierte Rolle entfernt und die verifizierte hinzufügt
    # HINWEIS: Dies setzt voraus, dass der User nur die eine unverifizierte Rolle hat.
    json_payload = {
        "roles": [VERIFIED_ROLE_ID]
    }
    
    update_res = requests.patch(discord_api_url, headers=headers, json=json_payload)

    # Prüfe auf Erfolg (200 OK oder 204 No Content)
    if update_res.status_code in [200, 204]:
        print(f"Benutzer {user_id} erfolgreich verifiziert.")
        return jsonify({'success': True})
    else:
        print(f"Discord API Fehler: {update_res.status_code} - {update_res.text}")
        return jsonify({'success': False, 'error': f'Rollen konnten nicht aktualisiert werden (API-Fehler {update_res.status_code})'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)