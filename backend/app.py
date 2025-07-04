from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests, os
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
# This line must be at the very top, before accessing any os.getenv calls.
load_dotenv()

app = Flask(__name__)

# --- Flask & JWT Configuration ---
# It's recommended to set app.secret_key from an environment variable in production
# Using a fallback default is good for local dev, but ensure it's a strong env var on Render.
app.secret_key = os.getenv("APP_SECRET_KEY", "super-secret-default-key-change-me-in-production-please")
CORS(app) # CORS enabled for all routes - consider more specific origins in production

# --- MySQL Configuration ---
# Ensure these environment variable names EXACTLY match what's on Render
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB")

# --- JWT Configuration ---
# Ensure this environment variable name EXACTLY matches what's on Render
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

mysql = MySQL(app)
jwt = JWTManager(app)

# --- GOOGLE OAUTH CONFIGURATION ---
# Fetch these directly from environment variables.
# These variables *must* be set on Render for deployment.
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI") # This must EXACTLY match your Google Cloud Console setting

# --- Debugging check for Google OAuth credentials at startup ---
# This will print to your console/Render logs if credentials are missing.
if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
    print("WARNING: Google OAuth credentials (CLIENT_ID, CLIENT_SECRET, REDIRECT_URI) are not fully configured. Check environment variables.")
    # For production, you might want to raise an error or exit here if they are critical
    # For now, the endpoint checks will catch it.

@app.route('/google-login')
def google_login():
    """
    Initiates the Google OAuth2 login flow.
    Make sure your Google Cloud Console redirect URI matches GOOGLE_REDIRECT_URI.
    All four scopes (email, profile, contacts.readonly, contacts.other.readonly) are requested.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_REDIRECT_URI:
        # This check is good for immediate feedback
        print("ERROR: GOOGLE_CLIENT_ID or GOOGLE_REDIRECT_URI missing for /google-login.")
        return jsonify({"error": "Google OAuth credentials (Client ID or Redirect URI) not configured."}), 500

    # Ensure scopes are space-separated before URL encoding
    # This matches the frontend `scope` construction
    scopes = [
        'email',
        'profile',
        'https://www.googleapis.com/auth/contacts.readonly',
        'https://www.googleapis.com/auth/contacts.other.readonly'
    ]
    encoded_scopes = '%20'.join(scopes) # Manually join with %20 as per Google's spec

    return redirect(
        f'https://accounts.google.com/o/oauth2/v2/auth'
        f'?client_id={GOOGLE_CLIENT_ID}'
        f'&redirect_uri={GOOGLE_REDIRECT_URI}'
        f'&response_type=code'
        f'&scope={encoded_scopes}' # Using the correctly encoded scopes
        f'&access_type=offline' # Request a refresh token for long-term access
        f'&prompt=consent'      # Forces user to re-consent, ensures refresh token on first login
    )

@app.route('/oauth2callback')
def oauth2callback():
    """
    Handles the Google OAuth2 callback, exchanges the authorization code for tokens,
    fetches user info, creates/logs in the user, and redirects to the dashboard with a JWT.
    Crucially, it now saves the Google refresh token.
    """
    code = request.args.get('code')
    if not code:
        print("ERROR: Authorization code not found in /oauth2callback request.")
        return "Authorization code not found.", 400

    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
        print("ERROR: Google OAuth credentials (CLIENT_ID, CLIENT_SECRET, or REDIRECT_URI) missing for /oauth2callback.")
        return jsonify({"error": "Google OAuth credentials not fully configured for callback."}), 500

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
        token_res.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        token_json = token_res.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token') # Retrieve the refresh_token!
        
        if not access_token:
            print(f"ERROR: No access token in response from Google token endpoint: {token_json}")
            return "Failed to retrieve access token.", 400

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error exchanging code for token: {http_err.response.status_code} - {http_err.response.text}")
        return jsonify({"error": "Error getting access token from Google.", "details": http_err.response.text}), 500
    except requests.exceptions.RequestException as req_err:
        print(f"Request Error exchanging code for token: {req_err}")
        return jsonify({"error": "Network or connection error during Google token exchange."}), 500
    except Exception as e:
        print(f"Unexpected error during token exchange: {e}")
        return jsonify({"error": "An unexpected error occurred during Google token exchange."}), 500

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
            print(f"ERROR: No email in user info from Google: {user_info}")
            return "Could not retrieve user email.", 400
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error fetching user info: {http_err.response.status_code} - {http_err.response.text}")
        return jsonify({"error": "Error fetching user information from Google.", "details": http_err.response.text}), 500
    except requests.exceptions.RequestException as req_err:
        print(f"Request Error fetching user info: {req_err}")
        return jsonify({"error": "Network or connection error fetching user information."}), 500

    cur = None
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if not existing_user:
            # Insert new user and save their refresh token
            # Ensure 'password' column is nullable or handled if not providing one for Google users
            cur.execute("INSERT INTO users (email, google_refresh_token) VALUES (%s, %s)",
                        (email, refresh_token)) # Save the refresh token here
            mysql.connection.commit()
            print(f"New user {email} created with Google OAuth.")
        else:
            # If user exists, update their refresh token if a new one was provided.
            # Google typically only provides refresh_token on first authorization or if revoked.
            if refresh_token: # Only update if a new refresh token was actually issued
                cur.execute("UPDATE users SET google_refresh_token = %s WHERE email = %s",
                            (refresh_token, email))
                mysql.connection.commit()
                print(f"Updated refresh token for existing user {email}.")
            else:
                print(f"User {email} exists, no new refresh token provided by Google.")

    except Exception as e:
        print(f"DATABASE ERROR during user check/creation/update for {email}: {e}")
        mysql.connection.rollback() # Rollback in case of error
        return jsonify({"error": "Database error during user registration/login."}), 500
    finally:
        if cur:
            cur.close()

    # Create JWT for your application's authentication
    # Using email as identity for simplicity; in a real app, use the user's DB ID.
    token = create_access_token(identity=email)

    # Redirect to frontend with your app's JWT
    # Ensure this URL is correctly configured on your frontend to handle the token
    # IMPORTANT: Double-check this frontend redirect URL
    return redirect(f"https://pulse.gitthit.com.ng/dashboard?token={token}")

# Helper function to refresh Google access token using the stored refresh token
def refresh_google_access_token(refresh_token):
    """
    Uses a Google refresh token to obtain a new, valid access token.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        print("ERROR: Google OAuth credentials not configured for token refresh.")
        return None

    token_refresh_data = {
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
    }
    try:
        refresh_res = requests.post('https://oauth2.googleapis.com/token', data=token_refresh_data)
        refresh_res.raise_for_status()
        refresh_json = refresh_res.json()
        new_access_token = refresh_json.get('access_token')
        
        # Google rarely issues a new refresh token. If it does, you should save it:
        # new_refresh_token = refresh_json.get('refresh_token')
        # if new_refresh_token:
        #     # You would need to update the user's record in the DB here
        #     # Example:
        #     # cur = mysql.connection.cursor()
        #     # cur.execute("UPDATE users SET google_refresh_token = %s WHERE email = %s", (new_refresh_token, user_email))
        #     # mysql.connection.commit()
        #     # cur.close()
        #     pass
        
        return new_access_token
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error refreshing Google access token: {http_err.response.status_code} - {http_err.response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"Request Error refreshing Google access token: {req_err}")
        return None
    except Exception as e:
        print(f"Unexpected error during Google token refresh: {e}")
        return None

# New Endpoint to fetch Google Contacts
@app.route('/api/contacts', methods=['GET'])
@jwt_required() # Protect this endpoint: only accessible with a valid JWT from your app
def get_google_contacts():
    """
    Fetches the current user's Google contacts using their stored refresh token.
    """
    current_user_email = get_jwt_identity() # Get user identity from your app's JWT

    cur = None
    refresh_token = None
    try:
        cur = mysql.connection.cursor()
        # Retrieve the Google refresh token for the current user
        cur.execute("SELECT google_refresh_token FROM users WHERE email = %s", (current_user_email,))
        result = cur.fetchone()
        if result and result[0]:
            refresh_token = result[0]
        else:
            print(f"ERROR: Google refresh token not found for user {current_user_email}. User needs to re-authenticate Google OAuth.")
            return jsonify({"msg": "Google refresh token not found for this user. Please re-authenticate Google OAuth."}), 400
    except Exception as e:
        print(f"DATABASE ERROR fetching refresh token for {current_user_email}: {e}")
        return jsonify({"msg": "Internal server error fetching user data."}), 500
    finally:
        if cur:
            cur.close()

    # Use the refresh token to get a fresh access token
    access_token = refresh_google_access_token(refresh_token)
    if not access_token:
        # If refresh fails, it likely means the refresh token is revoked or invalid.
        print(f"ERROR: Failed to refresh Google access token for user {current_user_email}. Refresh token might be invalid.")
        return jsonify({"msg": "Failed to refresh Google access token. Please re-authenticate Google OAuth."}), 401

    # Call Google People API for connections (contacts)
    contacts_url = "https://people.googleapis.com/v1/people/me/connections"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    params = {
        # Specify the fields you want for each person/contact
        "personFields": "names,emailAddresses,phoneNumbers,photos", # Added photos for completeness
        "pageSize": 100 # Adjust as needed, max 2000
        # You can add 'pageToken' for pagination if you have many contacts
    }

    try:
        contacts_res = requests.get(contacts_url, headers=headers, params=params)
        contacts_res.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        contacts_data = contacts_res.json()

        # Process the raw contacts data from Google API
        connections = contacts_data.get('connections', [])
        formatted_contacts = []
        for person in connections:
            name = person.get('names', [{}])[0].get('displayName', 'No Name')
            emails = [e.get('value') for e in person.get('emailAddresses', []) if e.get('value')]
            phones = [p.get('value') for p in person.get('phoneNumbers', []) if p.get('value')]
            # Add photo URL if available
            photo_url = person.get('photos', [{}])[0].get('url', None)

            formatted_contacts.append({
                "name": name,
                "emails": emails,
                "phones": phones,
                "photo_url": photo_url
            })

        return jsonify(formatted_contacts), 200

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error fetching Google contacts: {http_err.response.status_code} - {http_err.response.text}")
        # Google API might return specific error details in the response text
        return jsonify({"msg": "Error fetching contacts from Google API.", "details": http_err.response.text}), 500
    except requests.exceptions.RequestException as req_err:
        print(f"Request Error fetching Google contacts: {req_err}")
        return jsonify({"msg": "Network or connection error fetching contacts."}), 500
    except Exception as e:
        print(f"Unexpected error fetching Google contacts: {e}")
        return jsonify({"msg": "An unexpected error occurred while fetching contacts."}), 500


# Start the server (existing block)
if __name__ == '__main__':
    # When deploying, do NOT use app.run() directly. Use a production WSGI server like Gunicorn or uWSGI.
    # Render will use the 'gunicorn' command from your project's start command.
    app.run(
        host='0.0.0.0', # Listen on all available network interfaces
        port=5000,      # Listen on port 5000 (Render typically maps external port 80/443 to this)
        debug=True      # Set to False in production for security and performance
        # ssl_context=('/path/to/your/certificate.crt', '/path/to/your/private.key') # Uncomment and configure if you need HTTPS
    )
