from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

client = MongoClient(os.getenv("MONGO_URI"))
db = client['stress_db']
users_collection = db['users']
messages_collection = db['messages']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze_text', methods=['GET', 'POST'])
def analyze_text():
    import openai
    if 'username' not in session:
        flash('Please log in to access this feature.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_text = request.form['text']
        # response = openai.Completion.create(
        #     engine="text-davinci-003",
        #     prompt=f"Classify the following text as 'Stress' or 'No Stress': {user_text}",
        #     max_tokens=10
        # )
        # label = response.choices[0].text.strip()
        return render_template('result.html', label="NoStress", user_text=user_text)
    return render_template('analyze_text.html')

@app.route('/community', methods=['GET', 'POST'])
def community():
    if 'username' not in session:
        flash('Please log in to access the community chat.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        message_content = request.form['message']
        username = session['username']
        timestamp = datetime.utcnow()

        if message_content.strip():  # Ensure the message is not empty
            message = {
                'username': username,
                'message': message_content,
                'timestamp': timestamp
            }
            messages_collection.insert_one(message)

    messages = list(messages_collection.find().sort('timestamp', 1))
    return render_template('community.html', messages=messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if users_collection.find_one({'username': username}):
            flash('Error: Username already exists. Please choose a different one.', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({'username': username, 'password': hashed_password})
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_collection.find_one({'username': username})
        if user is None:
            flash('Error: Username does not exist.', 'error')
        elif not bcrypt.check_password_hash(user['password'], password):
            flash('Error: Incorrect password.', 'error')
        else:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)