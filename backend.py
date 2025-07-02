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
FRONTEND_URL = os.getenv("FRONTEND_URL") # z.B. https://incomparable-faun-4619e2.netlify.app

app = Flask(__name__)

# Konfiguriere CORS, um Anfragen NUR von deiner Webseite zu erlauben
CORS(app, resources={r"/verify": {"origins": FRONTEND_URL}})

# Helfer-Funktionen für die Token-Datei (angenommen, sie liegt im selben Verzeichnis)
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
        return jsonify({'success': False, 'error': 'Missing data'}), 400

    # 1. CAPTCHA bei Cloudflare verifizieren
    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload)
    if not verify_res.json().get('success'):
        return jsonify({'success': False, 'error': 'CAPTCHA verification failed'}), 400

    # 2. User-Token validieren und User-ID holen
    tokens_data = load_tokens()
    user_id = tokens_data.get(user_token)
    if not user_id:
        return jsonify({'success': False, 'error': 'Invalid or expired user token'}), 400

    # 3. Rollen des Users auf Discord ändern
    discord_api_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    # WICHTIG: Diese Payload ersetzt ALLE Rollen des Users.
    # Wenn der User andere Rollen behalten soll, muss die Logik angepasst werden.
    json_payload = {"roles": [VERIFIED_ROLE_ID]} 
    
    update_res = requests.patch(discord_api_url, headers=headers, json=json_payload)

    if update_res.status_code == 204:
        del tokens_data[user_token]
        save_tokens(tokens_data)
        return jsonify({'success': True})
    else:
        print(f"Discord API Error: {update_res.status_code} - {update_res.text}")
        return jsonify({'success': False, 'error': 'Failed to update roles on Discord'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)