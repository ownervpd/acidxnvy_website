from flask import Flask, request, jsonify, render_template_string
import requests
import os
import json

# Diese Variablen MÜSSEN auf Render unter "Environment" gesetzt werden!
CLOUDFLARE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
UNVERIFIED_ROLE_ID = os.getenv("UNVERIFIED_ROLE_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")
VERIFICATION_TOKENS_FILE = 'verification_tokens.json' # Der Bot und das Backend müssen auf diese Datei zugreifen können

app = Flask(__name__)

def load_tokens():
    if os.path.exists(VERIFICATION_TOKENS_FILE):
        with open(VERIFICATION_TOKENS_FILE, 'r') as f:
            try: return json.load(f)
            except json.JSONDecodeError: return {}
    return {}

def save_tokens(data):
    with open(VERIFICATION_TOKENS_FILE, 'w') as f:
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
    json_payload = {"roles": [VERIFIED_ROLE_ID]} # Ersetzt alle Rollen durch die eine verifizierte Rolle
    
    update_res = requests.patch(discord_api_url, headers=headers, json=json_payload)

    if update_res.status_code == 204:
        # Token nach erfolgreicher Verifizierung löschen
        del tokens_data[user_token]
        save_tokens(tokens_data)
        return jsonify({'success': True})
    else:
        print(f"Discord API Error: {update_res.status_code} - {update_res.text}")
        return jsonify({'success': False, 'error': 'Failed to update roles on Discord'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)