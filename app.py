#python app.py
#http://localhost:5000 in browser

from flask import Flask, request, jsonify, g, render_template  #request reads incoming data, jsonify turns python into json to send 
from functools import wraps
import bcrypt
import json
import re #for regex
import time #timestamps
import secrets 
import logging
from datetime import datetime
import os

app = Flask(__name__)

trackerForIPs = {} #dictionary with IP as key and value as list of timestamps

## helper 
def getUsers():
    with open('data/users.json', 'r') as f: #open users.json as read file 
        return json.load(f) #converts json into python
    

def saveUsers(users):
    with open('data/users.json', 'w') as f: #opens as write
        json.dump(users, f) #python to Json
def validateEmail(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)
def validateUsername(username): #false if invalid
    return re.match(r'^[\w]{3,20}$', username) #\w any letter/#, {3,20} -> length 

def validatePassword(password):
    if len(password) < 12: return False
    if not re.search(r'[A-Z]', password): return False 
    if not re.search(r'[a-z]', password): return False
    if not re.search(r'[0-9]', password): return False 
    if not re.search(r'[!@#$%^&*]', password): return False 
    return True # if all of the checks pass

def rateLimitChecker(ip):
    currTime = time.time()
    if ip not in trackerForIPs:
        trackerForIPs[ip] = []
    if len([attemptTime for attemptTime in trackerForIPs[ip] if currTime-attemptTime < 60]) >= 10:
        return False
    trackerForIPs[ip].append(currTime)
    return True

@app.route('/register', methods=['POST']) ##starts register route and only accepts data sent to server
def register():
    data = request.get_json() ##turns json request into python dict
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not validateUsername(username):
        return jsonify({'error': 'Invalid username'})
    if not validateEmail(email):
        return jsonify({'error': 'Invalid email'})
    if not validatePassword(password):
        return jsonify({'error': 'Password does not meet requirements'})
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'})
    
    users = getUsers()
    
    #check for username dupes when creating new users
    if username in users:
        return jsonify({'error': 'Username already taken'})
    
    #check for email dupes when creating new users
    for data in users.values():
        if data.get('email') == email:
            return jsonify({'error': 'Email already registered'})
    
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    users[username] = {
        "username": username,
        "email": email,
        "password_hash": hashed.decode('utf-8'),
        "created_at": time.time(),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": None
        }
    saveUsers(users)
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
def login():
    loginIP = request.remote_addr
    if not rateLimitChecker(loginIP):
        return jsonify({'error': 'Too many login attempts made, please wait a bit before attempting to login again.'})

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    users = getUsers()
    user = users.get(username, None)
    #check if username exists in user data
    if not user:
        return jsonify({'error': 'User does not exist.'})
    #check if account has been locked
    if user.get('locked_until') and time.time() < user['locked_until']:
        return jsonify({'error': 'Account locked due to too many failed attempts, please try again later.'})
    
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        user['failed_attempts'] += 1
        #lock user account until a specific time if this is their 5th failed attempt
        if user['failed_attempts'] >= 5:
            user['locked_until'] = time.time() + 900 
        saveUsers(users)
        return jsonify({'error': 'Invalid credentials'})
    user['failed_attempts'] = 0
    user['locked_until'] = None
    saveUsers(users)

    temp_token = secrets.token_urlsafe(32)
    response = jsonify({'success': True, 'message': 'Logged in successfully'})
    response.set_cookie(
        'session_token',
        temp_token,
        httponly=True,
        secure=False,
        samesite='Strict',
        max_age=1800
    )
    return response

def getCurrUser():  #stores current user id in global var g
    if getattr(g, 'user_id', None) is None:
        return None
    users = getUsers()
    return users.get(g.user_id)
    
def requireAuthentication(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if getattr(g, 'user_id', None) is None:
            return jsonify({'error': 'Please login.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def requireRole(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            users = getUsers()
            user = users.get(g.user_id)
            if not user or user.get('role') != role:
                return jsonify({'error': 'Permissions have not been granted.'})
            return f(*args, **kwargs)
        return decorated_function
    return decorator
    


@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
###########################