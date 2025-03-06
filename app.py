from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# CONFIGURE YOUR GENERIC API HERE
API_URL = 'https://api.artic.edu/api/v1/artworks'  # Example generic API
API_KEY = ''  # Optional: leave empty if not needed
API_KEY_HEADER = 'Authorization'  # Optional: change if needed (e.g., 'apikey', 'x-api-key')

def init_db():
    with sqlite3.connect('database.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL)''')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('database.db') as conn:
            try:
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                             (username, generate_password_hash(password)))
                flash('Account created successfully!', 'success')
                return redirect(url_for('signin'))
            except sqlite3.IntegrityError:
                flash('Username already exists!', 'danger')

    return render_template('signup.html')


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('database.db') as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user[2], password):
                session['username'] = username
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password.', 'danger')

    return render_template('signin.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('signin'))


@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('signin'))

    headers = {}
    if API_KEY:
        headers[API_KEY_HEADER] = API_KEY

    items = []
    try:
        response = requests.get(API_URL, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Check the format of JSON data and parse accordingly
        if isinstance(data, dict):
            # Handle single dictionary, may have a 'data' or similar key
            items = data.get('data', [])
        elif isinstance(data, list):
            # Handle list of dictionaries
            items = data
        else:
            flash('Unexpected JSON format.', 'danger')

    except requests.RequestException as e:
        flash(f'API request failed: {e}', 'danger')
    except ValueError:
        flash('Failed to parse JSON response.', 'danger')

    return render_template('home.html', items=items)


@app.route('/')
def index():
    return redirect(url_for('signin'))


init_db()

if __name__ == '__main__':
    app.run(debug=True, port=8080)
