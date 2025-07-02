from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import json

# Lade die Konfiguration aus den Environment Variables auf Render
CLOUDFLARE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
UNVERIFIED_ROLE_ID = os.getenv("UNVERIFIED_ROLE_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")
FRONTEND_URL = os.getenv("FRONTEND_URL")

app = Flask(__name__)
CORS(app, origins=[FRONTEND_URL] if FRONTEND_URL else "*")

def load_tokens():
    # In einer serverless Umgebung wie Render ist ein lokales Dateisystem nicht zuverlässig.
    # Für einen echten Einsatz wäre eine Datenbank (z.B. Redis oder PostgreSQL auf Render) besser.
    # Für den Moment gehen wir davon aus, dass die Datei zugänglich ist.
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
        return jsonify({'success': False, 'error': 'CAPTCHA-Verifizierung fehlgeschlagen'}), 400

    # Hier würde die Logik kommen, um den user_token zu validieren und die user_id zu bekommen.
    # Da Bot und Backend getrennt sind, muss der Bot die user_id direkt in den Token verschlüsseln.
    # Wir nehmen für den Moment an, dass der user_token die user_id ist.
    user_id = user_token

    # 3. Rollen des Users auf Discord ändern
    discord_api_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    json_payload = {"roles": [VERIFIED_ROLE_ID]} 
    
    update_res = requests.patch(discord_api_url, headers=headers, json=json_payload)

    # KORREKTUR: Wir akzeptieren jetzt 200 (OK) und 204 (No Content) als Erfolg.
    if update_res.status_code in [200, 204]:
        # Hier würde man den Token aus einer Datenbank löschen
        return jsonify({'success': True})
    else:
        # Gibt jetzt eine spezifischere Fehlermeldung zurück
        error_details = update_res.text
        print(f"Discord API Error: {update_res.status_code} - {error_details}")
        return jsonify({'success': False, 'error': f'Failed to update roles. API responded with {update_res.status_code}'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)