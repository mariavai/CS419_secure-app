#python app.py
#http://localhost:5000 in browser

from flask import Flask, request, jsonify, g, render_template, send_file  #request reads incoming data, jsonify turns python into json to send 
from functools import wraps
import bcrypt
import json
import re #for regex
import time #timestamps
import secrets
import logging
from datetime import datetime
import os
import uuid
import io
from werkzeug.utils import secure_filename
import hashlib
from classes import EncryptedStorage, SessionManager, SecurityLogger, DocumentManager


app = Flask(__name__)

trackerForIPs = {} #dictionary with IP as key and value as list of timestamps
sessionManager = SessionManager()
securityLogger = SecurityLogger()
encryptedStorage = EncryptedStorage()
documentManager = DocumentManager()

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_GUEST = "guest"



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

@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_token')
    if token:
        sessionManager.destroySession(token)
        securityLogger.logEvent('SESSION_DESTROYED', g.user_id, {})
    response = jsonify({'success': True, 'message': 'Successful logout!'})
    response.set_cookie('session_token', '', expires=0, httponly=True, samesite='Strict')
    return response


def getCurrUser():  #stores current user id in global var g
    user_id = getattr(g, 'user_id', None)
    if not user_id:
        return None
    users = getUsers()
    return users.get(g.user_id)

def getCurrUserRole():
    #returns global role of user otherwise guest
    user = getCurrUser()
    if not user:
        return ROLE_GUEST
    return user.get("role", ROLE_USER)

    
def requireAuthentication(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if getattr(g, 'user_id', None) is None:
            return jsonify({'error': 'Please login.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def requireRole(*roles):
  #restricts access depending on role
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # get the current user object
            user = getCurrUser()

            # if no user is logged in no access
            if not user:
                securityLogger.logEvent(
                    "ACCESS_DENIED",
                    None,
                    {"required_roles": roles, "reason": "Not authenticated"},
                    "WARNING"
                )
                return jsonify({"error": "Please login."}), 401

            #get global role
            user_role = user.get("role")

            # not in list deny access
            if user_role not in roles:
                securityLogger.logEvent(
                    "ACCESS_DENIED",
                    g.user_id,
                    {"required_roles": roles, "user_role": user_role, "reason": "Insufficient privileges"},
                    "WARNING"
                )
                return jsonify({"error": "Permissions have not been granted."}), 403

            # Otherwise allow the request
            return f(*args, **kwargs)
        return wrapper
    return decorator

def getDocument(docId):
    #gets document metadata otherwise nothing
    metadata = documentManager.loadMetadata()
    return metadata.get(docId)


def getUserDocumentRole(user_id, docMeta):
    #returns role for specific doc; owner, editor,view, none
    if not docMeta:
        return None

    # owner always has full control
    if docMeta.get("owner") == user_id:
        return "owner"

    # otherwise check sharedWith dictionary
    return docMeta.get("sharedWith", {}).get(user_id)


def isOwner(user_id, docMeta):
    #checks if owner
    return docMeta.get("owner") == user_id


def isEditor(user_id, docMeta):
    #checks if you can edit; owner or editor count
    return getUserDocumentRole(user_id, docMeta) in ["editor", "owner"]


def isViewer(user_id, docMeta):
    #check if you view, editor, owner and viewer count
    return getUserDocumentRole(user_id, docMeta) in ["viewer", "editor", "owner"]

def requireDocumentPermission(docArgName, requiredRole):
    #stops user from acessing a document thye shouldnt be able to 
    
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            # must be logged in
            user = getCurrUser()
            if not user:
                return jsonify({"error": "Please login."}), 401

            # get docId
            data = request.get_json()
            docId = data.get(docArgName)
            docMeta = getDocument(docId)

            # check if doc exists
            if not docMeta:
                return jsonify({"error": "Document not found"}), 404

            # if admin don't check
            if getCurrUserRole() == ROLE_ADMIN:
                return f(*args, **kwargs)

            user_id = user["username"]

            #  if owner dont check
            if isOwner(user_id, docMeta):
                return f(*args, **kwargs)

            # check for viewer permissions
            if requiredRole == "viewer" and not isViewer(user_id, docMeta):
                securityLogger.logEvent(
                    "ACCESS_DENIED",
                    user_id,
                    {"resource": docId, "reason": "Viewer permission required"},
                    "WARNING"
                )
                return jsonify({"error": "You do not have permission to view this document."}), 403

            # check for editor permission
            if requiredRole == "editor" and not isEditor(user_id, docMeta):
                securityLogger.logEvent(
                    "ACCESS_DENIED",
                    user_id,
                    {"resource": docId, "reason": "Editor permission required"},
                    "WARNING"
                )
                return jsonify({"error": "You do not have permission to modify this document."}), 403

            # if checks pass allow 
            return f(*args, **kwargs)
        return wrapper
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
        
        

@app.route('/upload', methods=['POST'])
@requireAuthentication
@requireRole(ROLE_ADMIN, ROLE_USER)   # guests NOT allowed
#@requireDocumentPermission("docId", "editor")   # must be editor or owner
def uploadDocument():
    if 'file' not in request.files:
        return jsonify({'error': 'No file found'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    #sanitize filename --> prevent path tranversal
    fileName = secure_filename(file.filename)
    docID = str(uuid.uuid4())   #create unique doc ID
    role = getCurrUserRole()
    filePath = documentManager.getSecureFilePath(docID, role)
    
    
    try:
        #encrypt file bytes and then upload
        encrypted_content = encryptedStorage.encryptDataBytes(file.read())
        
        with open(filePath, 'wb') as f:
            f.write(encrypted_content)
        #add metadata
        documentManager.createDocumentEntry(docID, g.user_id, fileName)
        documentManager.addVersion(docID, filePath, g.user_id)
        documentManager.logAction(docID, g.user_id, "UPLOAD")

        if role == 'admin':
            securityLogger.logEvent('ADMIN_UPLOAD_SUCCESS', g.user_id, {'docID': docID, 'fileName': fileName})
        else:
            securityLogger.logEvent('USER_UPLOAD_SUCCESS', g.user_id, {'docID': docID, 'fileName': fileName})
        return jsonify({'success': True, 'fileName': fileName})
    
    except Exception as e:
        if role == 'admin':
            securityLogger.logEvent('ADMIN_UPLOAD_FAILURE', g.user_id, {'error': str(e)}, 'ERROR')
        else:
            securityLogger.logEvent('USER_UPLOAD_FAILURE', g.user_id, {'error': str(e)}, 'ERROR')
        return jsonify({'error': 'Upload failed'})
    

    
    
@app.route('/download/<docID>', methods=['GET'])
@requireAuthentication
@requireRole(ROLE_ADMIN, ROLE_USER, ROLE_GUEST)
@requireDocumentPermission("docId", "viewer")
def downloadDocument(docID):
    metadata = documentManager.loadMetadata()
    doc = metadata.get(docID)
    if not doc:
        return jsonify({'error': 'Document not found'})

    currUser = g.user_id
    role = getCurrUserRole()

    #check whether current user has access
    userHasAccess = role == 'admin' or doc['owner'] == currUser or currUser in doc['sharedWith']
    if not userHasAccess:
        securityLogger.logEvent('UNAUTHORIZED_ACCESS', currUser, {'docID': docID}, 'CRITICAL')
        return jsonify({'error': 'Access denied.'})

    try:
        #get path from metadata which was generated by getFilePath during upload
        filePath = doc['versions'][-1]['path']
        
        with open(filePath, 'rb') as f:
            encryptedData = f.read()
        decryptedData = encryptedStorage.decryptDataBytes(encryptedData)
        documentManager.logAction(docID, currUser, "DOWNLOAD")
        securityLogger.logEvent('DOWNLOAD_SUCCESS', currUser, {'docID': docID})

        #file to send to browser w/ original general file name
        return send_file(io.BytesIO(decryptedData), download_name=doc['fileName'], as_attachment=True)

    except Exception as e:
        securityLogger.logEvent('DOWNLOAD_ERROR', currUser, {'error': str(e)}, 'ERROR')
        return jsonify({'error': 'Could not process download.'})


@app.route('/share', methods=['POST'])
@requireAuthentication
def shareDocument():
    #allows owner + admin to share a doc
    #adds users as either editor or viewer
    user = getCurrUser()  # current logged-in user
    data = request.get_json()

    docId = data.get("docId")
    targetUser = data.get("targetUser")
    role = data.get("role")  # view or editor

    
    if role not in ["viewer", "editor"]:
        return jsonify({"error": "Invalid role"}), 400

    # load document metadata
    docMeta = getDocument(docId)
    if not docMeta:
        return jsonify({"error": "Document not found"}), 404

    # only owner or admin can share
    if getCurrUserRole() != ROLE_ADMIN and not isOwner(user["username"], docMeta):
        securityLogger.logEvent(
            "ACCESS_DENIED",
            user["username"],
            {"resource": docId, "reason": "Only owner/admin can share"},
            "WARNING"
        )
        return jsonify({"error": "You do not have permission to share this document."}), 403

    # share
    documentManager.shareDocument(docId, targetUser, role)

    # log to document log
    documentManager.logAction(docId, user["username"], f"SHARED_WITH_{targetUser}_{role.upper()}")

    # log to security log
    securityLogger.logEvent(
        "DATA_ACCESS",
        user["username"],
        {"resource": docId, "action": "share", "targetUser": targetUser, "role": role}
    )

    return jsonify({"success": True, "message": f"Document shared with {targetUser} as {role}."})

@app.route('/unshare', methods=['POST'])
@requireAuthentication
def unshareDocument():
    #remove access to document
    user = getCurrUser()
    data = request.get_json()

    docId = data.get("docId")
    targetUser = data.get("targetUser")

    # load document metadata
    docMeta = getDocument(docId)
    if not docMeta:
        return jsonify({"error": "Document not found"}), 404

    # only owner or admin can unshare
    if getCurrUserRole() != ROLE_ADMIN and not isOwner(user["username"], docMeta):
        securityLogger.logEvent(
            "ACCESS_DENIED",
            user["username"],
            {"resource": docId, "reason": "Only owner/admin can unshare"},
            "WARNING"
        )
        return jsonify({"error": "You do not have permission to unshare this document."}), 403

    #unshare
    success = documentManager.unshareDocument(docId, targetUser)
    if not success:
        return jsonify({"error": "User does not have access to this document."}), 400

    #log to document log
    documentManager.logAction(docId, user["username"], f"UNSHARED_{targetUser}")

    #log to security log
    securityLogger.logEvent(
        "DATA_ACCESS",
        user["username"],
        {"resource": docId, "action": "unshare", "targetUser": targetUser}
    )

    return jsonify({"success": True, "message": f"{targetUser} no longer has access."})

@app.route('/downgradeToGuest', methods=['POST'])
@requireAuthentication
@requireRole(ROLE_ADMIN)   #only admins
def downgradeToGuest():
    data = request.get_json()
    username = data.get("username")

    users = getUsers()

    # check if user exists
    if username not in users:
        return jsonify({"error": "User not found"}), 404

    # admin cannot downgrade themself
    if username == g.user_id:
        return jsonify({"error": "You cannot downgrade your own account."}), 400

    # Update role
    users[username]["role"] = ROLE_GUEST
    saveUsers(users)

    # Log event
    securityLogger.logEvent(
        "ROLE_DOWNGRADED",
        g.user_id,
        {"target": username, "new_role": ROLE_GUEST},
        "WARNING"
    )

    return jsonify({"success": True, "message": f"{username} has been downgraded to guest."})

@app.route('/upgradeRole', methods=['POST'])
@requireAuthentication
@requireRole(ROLE_ADMIN)   # ONLY admins
def upgradeRole():
    data = request.get_json()
    username = data.get("username")
    newRole = data.get("role")   #user or admin

    users = getUsers()

    # Check if user exists
    if username not in users:
        return jsonify({"error": "User not found"}), 404

    # validate role
    if newRole not in [ROLE_USER, ROLE_ADMIN]:
        return jsonify({"error": "Invalid role"}), 400

    # cannot change themself
    if username == g.user_id and newRole != ROLE_ADMIN:
        return jsonify({"error": "You cannot change your own role."}), 400

    # update role
    users[username]["role"] = newRole
    saveUsers(users)

    # Log event
    securityLogger.logEvent(
        "ROLE_UPGRADED",
        g.user_id,
        {"target": username, "new_role": newRole},
        "INFO"
    )

    return jsonify({"success": True, "message": f"{username} has been upgraded to {newRole}."})

@app.route('/findUserFileList', methods=['GET'])
@requireAuthentication
def findUserFileList():
    docsList = documentManager.loadMetadata()
    currUser = g.user_id
    role = getCurrUserRole()
    visibleFiles = []
    
    for docID, doc in docsList.items():
        if role == 'admin' or doc['owner'] == currUser or currUser in doc.get('sharedWith', {}):
            visibleFiles.append({
                'docID': docID,
                'fileName': doc['fileName'],
                'owner': doc['owner'],
                'createdAt': doc['createdAt'],
                'permission': 'admin' if role == 'admin' else ('owner' if doc['owner'] == currUser else doc['sharedWith'].get(currUser))
            })
    return jsonify(visibleFiles)



@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
###########################