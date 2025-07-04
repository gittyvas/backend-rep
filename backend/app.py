from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token
import requests, os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("JWT_SECRET_KEY") # Consider using a more robust method for secret key handling in production
CORS(app)

# MySQL + JWT Setup
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY") # Ensure this is a strong, unique key

mysql = MySQL(app)
jwt = JWTManager(app)

# GOOGLE OAUTH CONFIG
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI") # This should match your Google Cloud Console setting

@app.route('/google-login')
def google_login():
    """
    Initiates the Google OAuth2 login flow.
    """
    return redirect(
        f'https://accounts.google.com/o/oauth2/v2/auth'
        f'?client_id={GOOGLE_CLIENT_ID}'
        f'&redirect_uri={GOOGLE_REDIRECT_URI}'
        f'&response_type=code'
        f'&scope=email%20profile%20https://www.googleapis.com/auth/contacts.readonly' # Consider if you need contacts.readonly scope
        f'&access_type=offline' # Request refresh token for long-lived access
        f'&prompt=consent'      # Forces user to re-consent, good for development
    )

@app.route('/oauth2callback')
def oauth2callback():
    """
    Handles the Google OAuth2 callback, exchanges the authorization code for tokens,
    fetches user info, creates/logs in the user, and redirects to the dashboard with a JWT.
    """
    code = request.args.get('code')
    if not code:
        return "Authorization code not found.", 400

    # Exchange code for token
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }

    try:
        token_res = requests.post('https://oauth2.googleapis.com/token', data=token_data)
        token_res.raise_for_status() # Raise an exception for HTTP errors
        token_json = token_res.json()
        access_token = token_json.get('access_token')
    except requests.exceptions.RequestException as e:
        print(f"Error exchanging code for token: {e}")
        return "Error getting access token from Google.", 500

    if not access_token:
        print(f"No access token in response: {token_json}")
        return "Failed to retrieve access token.", 400

    # Fetch user info
    try:
        user_info_res = requests.get(
            'https://www.googleapis.com/oauth2/v1/userinfo',
            params={'access_token': access_token}
        )
        user_info_res.raise_for_status()
        user_info = user_info_res.json()
        email = user_info.get("email")
        if not email:
            print(f"No email in user info: {user_info}")
            return "Could not retrieve user email.", 400
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user info: {e}")
        return "Error fetching user information from Google.", 500


    # Create user if not exists (or retrieve existing user)
    cur = None # Initialize cur outside try block
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if not existing_user:
            cur.execute("INSERT INTO users (email) VALUES (%s)", (email,))
            mysql.connection.commit()
        # You might want to get the user's ID here if you need it for JWT identity
        # Example: if not existing_user: user_id = cur.lastrowid else: user_id = existing_user[0]

    except Exception as e:
        print(f"Database error during user check/creation: {e}")
        mysql.connection.rollback() # Rollback in case of error
        return "Database error during login.", 500
    finally:
        if cur:
            cur.close()

    # Create JWT
    token = create_access_token(identity=email) # Using email as identity, consider using user ID from DB

    # Redirect to frontend with token
    # Ensure this URL is correctly configured on your frontend to handle the token
    return redirect(f"https://pulse.gitthit.com.ng/dashboard?token={token}")

# Start the server
if __name__ == '__main__':
    # When deploying, do NOT use app.run() directly. Use a production WSGI server like Gunicorn or uWSGI.
    app.run(
        host='0.0.0.0', # Listen on all available network interfaces
        port=5000,      # Listen on port 5000
        debug=True      # Set to False in production for security and performance
        # ssl_context=('/path/to/your/certificate.crt', '/path/to/your/private.key') # Uncomment and configure if you need HTTPS
    )
