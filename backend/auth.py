import firebase_admin;
from firebase_admin import credentials, firestore, auth

cred = credentials.Certificate('firebase-config.json')
firebase_admin.initialize_app(cred)

db = firestore.client()

def login_user(email, password):
    """
    Logs in a user using Firebase Authentication.
    """
    try:
        user = auth.get_user_by_email(email)
        if user and user.password == password:
            return user
        else:
            return None
    except Exception as e:
        print(f"Error logging in user: {e}")
        return None