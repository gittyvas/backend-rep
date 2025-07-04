from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token
import requests, os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("JWT_SECRET_KEY")
CORS(app)

# MySQL + JWT Setup
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

mysql = MySQL(app)
jwt = JWTManager(app)

# GOOGLE OAUTH CONFIG
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

@app.route('/google-login')
def google_login():
    return redirect(
        f'https://accounts.google.com/o/oauth2/v2/auth'
        f'?client_id={GOOGLE_CLIENT_ID}'
        f'&redirect_uri={GOOGLE_REDIRECT_URI}'
        f'&response_type=code'
        f'&scope=email%20profile%20https://www.googleapis.com/auth/contacts.readonly'
        f'&access_type=offline'
        f'&prompt=consent'
    )

@app.route('/oauth2callback')
def oauth2callback():
    code = request.args.get('code')

    # Exchange code for token
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }

    token_res = requests.post('https://oauth2.googleapis.com/token', data=token_data)
    token_json = token_res.json()
    access_token = token_json.get('access_token')

    if not access_token:
        return "Error getting access token", 400

    # Fetch user info
    user_info_res = requests.get(
        'https://www.googleapis.com/oauth2/v1/userinfo',
        params={'access_token': access_token}
    )
    user_info = user_info_res.json()
    email = user_info.get("email")

    # Create user if not exists
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cur.fetchone()

    if not existing_user:
        cur.execute("INSERT INTO users (email) VALUES (%s)", (email,))
        mysql.connection.commit()

    cur.close()

    # Create JWT
    token = create_access_token(identity=email)

    # Redirect to frontend with token
    return redirect(f"https://pulse.gitthit.com.ng/dashboard?token={token}")

# Start the server
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context=(
            "/etc/letsencrypt/live/pulse.gitthit.com.ng/fullchain.pem",  # Path to your SSL cert
            "/etc/letsencrypt/live/pulse.gitthit.com.ng/privkey.pem"      # Path to your private key
        )
    )
