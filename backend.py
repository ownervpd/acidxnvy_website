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

if not all([CLOUDFLARE_SECRET_KEY, BOT_TOKEN, GUILD_ID, VERIFIED_ROLE_ID, SECRET_KEY]):
    raise ValueError("Eine oder mehrere notwendige Environment Variables fehlen!")

fernet = Fernet(SECRET_KEY.encode())
app = Flask(__name__)
CORS(app)

# --- NEUE FUNKTION ---
# Antwortet auf Pings von UptimeRobot oder wenn jemand die Haupt-URL besucht
@app.route('/')
def index():
    return "Backend is running."
# --- ENDE NEUE FUNKTION ---

@app.route('/verify', methods=['POST'])
def verify_captcha():
    data = request.json
    captcha_token = data.get('captchaToken')
    user_token = data.get('userToken')

    if not all([captcha_token, user_token]):
        return jsonify({'success': False, 'error': 'Fehlende Daten'}), 400

    verify_payload = {'secret': CLOUDFLARE_SECRET_KEY, 'response': captcha_token}
    verify_res = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=verify_payload)
    verify_data = verify_res.json()

    if not verify_data.get('success'):
        return jsonify({'success': False, 'error': 'CAPTCHA-Verifizierung fehlgeschlagen'}), 400

    try:
        decrypted_user_id_bytes = fernet.decrypt(user_token.encode())
        user_id = decrypted_user_id_bytes.decode()
    except Exception:
        return jsonify({'success': False, 'error': 'Ungültiger Verifizierungs-Token'}), 400

    add_role_url = f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}/roles/{VERIFIED_ROLE_ID}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    
    update_res = requests.put(add_role_url, headers=headers)

    if update_res.status_code == 204:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': f'Rollen konnten nicht aktualisiert werden (API-Fehler {update_res.status_code})'}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)