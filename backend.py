from flask import Flask, request, jsonify
import requests
import os
from dotenv import load_dotenv

# Lade die geheimen Schlüssel aus einer .env Datei
load_dotenv()

# Konfiguration (diese musst du beim Hoster als "Environment Variables" setzen)
CLOUDFLARE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
UNVERIFIED_ROLE_ID = os.getenv("UNVERIFIED_ROLE_ID")
VERIFIED_ROLE_ID = os.getenv("VERIFIED_ROLE_ID")

app = Flask(__name__)

@app.route('/verify', methods=['POST'])
def verify_captcha():
    data = request.json
    captcha_token = data.get('captchaToken')
    user_id = data.get('userId')

    if not all([captcha_token, user_id]):
        return jsonify({'success': False, 'error': 'Missing data'}), 400

    # 1. CAPTCHA bei Cloudflare verifizieren
    verify_payload = {
        'secret': CLOUDFLARE_SECRET_KEY,
        'response': captcha_token
    }
    verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload)
    verify_data = verify_res.json()

    if not verify_data.get('success'):
        return jsonify({'success': False, 'error': 'CAPTCHA verification failed'}), 400

    # 2. Wenn CAPTCHA erfolgreich, Rollen des Users auf Discord ändern
    discord_api_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {BOT_TOKEN}"
    }
    # Hier definieren wir, welche Rolle entfernt und welche hinzugefügt wird
    json_payload = {
        "roles": [VERIFIED_ROLE_ID] # User erhält nur noch die verifizierte Rolle
    }
    
    update_res = requests.patch(discord_api_url, headers=headers, json=json_payload)

    if update_res.status_code == 204: # 204 No Content ist die Erfolgsantwort von Discord
        return jsonify({'success': True})
    else:
        print(f"Discord API Error: {update_res.status_code} - {update_res.text}")
        return jsonify({'success': False, 'error': 'Failed to update roles on Discord'}), 500

if __name__ == "__main__":
    # Port wird vom Hoster vorgegeben, für lokale Tests kann man 5000 nehmen
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)