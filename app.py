#python app.py
#http://localhost:5000 in browser

from flask import Flask, request, jsonify #request reads incoming data, jsonify turns python into json to send 
import bcrypt
import json
import re #for regex
import time #timestamps

app = Flask(__name__)

## helper 
def createUsers():
    with open('data/users.json', 'r') as f: #open users.json as read file 
        return json.load(f) #converts json into python

def saveUsers(users):
    with open('data/users.json', 'w') as f: #opens as write
        json.dump(users, f) #python to Json

def validateUsername(username): #false if invalid
    return re.match(r'^[\w]{3,20}$', username) #\w any letter/#, {3,20} -> length 

def validatePassword(password):
    if len(password) < 12: return False
    if not re.search(r'[A-Z]', password): return False 
    if not re.search(r'[a-z]', password): return False
    if not re.search(r'[0-9]', password): return False 
    if not re.search(r'[!@#$%^&*]', password): return False 
    return True # if all of the checks pass

@app.route('/register', methods=['POST']) ##starts register route and only accepts data sent to server
def register():
    data = request.get_json() ##turns json request into python dict
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not validateUsername(username):
        return jsonify({'error': 'Invalid username'})
    if not validatePassword(password):
        return jsonify({'error': 'Password does not meet requirements'})
    
    users = createUsers()
    
    #check for username dupes when creating new users
    if username in users:
        return jsonify({'error': 'Username already taken'})
    
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

@app.route('/')
def home():
    return "Hello, world!"

if __name__ == '__main__':
    app.run(debug=True)
###########################