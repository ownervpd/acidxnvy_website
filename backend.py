from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from cryptography.fernet import Fernet

# Lade die Konfiguration aus den Environment Variables auf Render
CLOUDFLARE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
UNVERIFIED_ROLE_ID = os.getenv("UNVERIFIED_ROLE_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY nicht in den Environment Variables gefunden!")
fernet = Fernet(SECRET_KEY.encode())

app = Flask(__name__)
CORS(app)

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

    # 2. User-Token entschlüsseln, um die User-ID zu erhalten
    try:
        decrypted_user_id_bytes = fernet.decrypt(user_token.encode())
        user_id = decrypted_user_id_bytes.decode()
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid user token'}), 400

    # 3. Rollen des Users auf Discord ändern
    discord_api_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    json_payload = {"roles": [VERIFIED_ROLE_ID]}
    
    update_res = requests.patch(discord_api_url, headers=headers, json=json_payload)

    if update_res.status_code == 204:
        return jsonify({'success': True})
    else:
        print(f"Discord API Error: {update_res.status_code} - {update_res.text}")
        return jsonify({'success': False, 'error': 'Failed to update roles on Discord'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)