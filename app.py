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
from classes import EncryptedStorage, SessionManager, SecurityLogger

app = Flask(__name__)

trackerForIPs = {} #dictionary with IP as key and value as list of timestamps
sessionManager = SessionManager()
securityLogger = SecurityLogger()
storage = EncryptedStorage()

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
        # logEvent() takes 4 args: (event_type, user_id, details, severity) || event_type: string label that describes what happened 
        # user_id: None -> not logged in yet || details: a dict {}: field -> which input failed, reason -> why || severity: 'WARNING'
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'username', 'reason': 'Invalid format'}, 'WARNING')
        return jsonify({'error': 'Invalid username'})
    if not validateEmail(email):
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'email', 'reason': 'Invalid format'}, 'WARNING')
        return jsonify({'error': 'Invalid email'})
    if not validatePassword(password):
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'password', 'reason': 'Does not meet requirements'}, 'WARNING')
        return jsonify({'error': 'Password does not meet requirements'})
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'})
    
    users = getUsers()
    
    #check for username dupes when creating new users
    if username in users:
        securityLogger.logEvent('REGISTRATION_FAILED', None, {'reason': 'Username already taken', 'username': username}, 'WARNING')
        return jsonify({'error': 'Username already taken'})
    
    
    #check for email dupes when creating new users
    for data in users.values():
        if data.get('email') == email:
            securityLogger.logEvent('REGISTRATION_FAILED', None, {'reason': 'Email already registered'}, 'WARNING')
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

    #user_id = username || no severity, default is info
    securityLogger.logEvent('REGISTRATION_SUCCESS', username, {'username': username})
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
def login():
    loginIP = request.remote_addr
    if not rateLimitChecker(loginIP):

        #loginIP stores IP to track later
        securityLogger.logEvent('SUSPICIOUS_ACTIVITY', None, {'reason': 'Rate limit exceeded', 'ip': loginIP}, 'WARNING')
        return jsonify({'error': 'Too many login attempts made, please wait a bit before attempting to login again.'})

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    users = getUsers()
    user = users.get(username, None)
    #check if username exists in user data
    if not user:
        #user_id = none, username doesn't exist
        securityLogger.logEvent('LOGIN_FAILED', None, {'username': username, 'reason': 'User does not exist'}, 'WARNING')
        return jsonify({'error': 'User does not exist.'})
    #check if account has been locked
    if user.get('locked_until') and time.time() < user['locked_until']:
        securityLogger.logEvent('LOGIN_FAILED', username, {'reason': 'Account is locked'}, 'WARNING')
        return jsonify({'error': 'Account locked due to too many failed attempts, please try again later.'})
    
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        user['failed_attempts'] += 1
        securityLogger.logEvent('LOGIN_FAILED', username, {'reason': 'Invalid password', 'failed_attempts': user['failed_attempts']}, 'WARNING')
        #lock user account until a specific time if this is their 5th failed attempt
        if user['failed_attempts'] >= 5:
            user['locked_until'] = time.time() + 900 
            securityLogger.logEvent('ACCOUNT_LOCKED', username, {'reason': '5 failed login attempts'}, 'ERROR')
        saveUsers(users)
        return jsonify({'error': 'Invalid credentials'})
    user['failed_attempts'] = 0
    user['locked_until'] = None
    saveUsers(users)

    token = sessionManager.createSession(user['username'])
    securityLogger.logEvent('SESSION_CREATED', username, {})
    securityLogger.logEvent('LOGIN_SUCCESS', username, {'username': username})

    response = jsonify({'success': True, 'message': 'Successful login!'})
    
    response.set_cookie(
        'session_token',
        token,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=1800
    )
    return response

def getCurrUser():  #stores current user id in global var g
    user_id = getattr(g, 'user_id', None)
    if not user_id:
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
                #g.user_id = logged in user
                securityLogger.logEvent('ACCESS_DENIED', g.user_id, {'required_role': role, 'reason': 'Insufficient privileges'}, 'WARNING')
                return jsonify({'error': 'Permissions have not been granted.'})
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.before_request
def loadUserSession():
    token = request.cookies.get('session_token')
    if token:
        sessionData = sessionManager.validateSession(token)
        if sessionData:
            g.user_id = sessionData['user_id']
        else:
            g.user_id = None
            securityLogger.logEvent('SUSPICIOUS_ACTIVITY', None, {'reason': 'Invalid or expired session token'}, 'WARNING')
    else:
        g.user_id = None
        


    


@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
###########################