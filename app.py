#python app.py
#http://localhost:5000 in browser

from flask import Flask, request, jsonify, g, render_template, send_file, redirect  #request reads incoming data, jsonify turns python into json to send 
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
from classes import EncryptedStorage, SessionManager, SecurityLogger, DocumentManager, AccessLogger


app = Flask(__name__)




trackerForIPs = {} #dictionary with IP as key and value as list of timestamps
documentManager = DocumentManager()
sessionManager = SessionManager()
securityLogger = SecurityLogger()
accessLogger = AccessLogger()
encryptedStorage = EncryptedStorage()

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_GUEST = "guest"

ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@app.after_request
def set_security_headers(response):
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline';"
        "style-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
    )

    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Legacy XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # HSTS (HTTP Strict Transport Security)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response


# log security configuration load 
securityLogger.logEvent(
    "SECURITY_CONFIG_LOADED",
    None,
    {
        "headers": [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Strict-Transport-Security"
        ]
    },
    "INFO"
)

## helper 
def is_allowed_file(filename):
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS
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
    if len(email) > 254:
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'email', 'reason': 'Too long'}, 'WARNING')
        return jsonify({'error': 'Email too long'}), 400
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not validateUsername(username):
        # logEvent() takes 4 args: (event_type, user_id, details, severity) || event_type: string label that describes what happened 
        # user_id: None -> not logged in yet || details: a dict {}: field -> which input failed, reason -> why || severity: 'WARNING'
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'username', 'reason': 'Invalid format'}, 'WARNING')
        return jsonify({'error': 'Invalid username'}), 400
    if not validateEmail(email):
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'email', 'reason': 'Invalid format'}, 'WARNING')
        return jsonify({'error': 'Invalid email'}), 400
    if not validatePassword(password):
        securityLogger.logEvent('INPUT_VALIDATION_FAILURE', None, {'field': 'password', 'reason': 'Does not meet requirements'}, 'WARNING')
        return jsonify({'error': 'Password does not meet requirements'}), 400
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 401
    
    users = getUsers()
    
    #check for username dupes when creating new users
    if username in users:
        securityLogger.logEvent('REGISTRATION_FAILED', None, {'reason': 'Username already taken', 'username': username}, 'WARNING')
        return jsonify({'error': 'Username already taken'}), 400
    
    
    #check for email dupes when creating new users
    for data in users.values():
        if data.get('email') == email:
            securityLogger.logEvent('REGISTRATION_FAILED', None, {'reason': 'Email already registered'}, 'WARNING')
            return jsonify({'error': 'Email already registered'}), 400
    
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    users[username] = {
        "username": username,
        "email": email,
        "password_hash": hashed.decode('utf-8'),
        "created_at": time.time(),
        "role": ROLE_GUEST,
        "failed_attempts": 0,
        "locked_until": None
        }
    saveUsers(users)

    #user_id = username || no severity, default is info
    securityLogger.logEvent('REGISTRATION_SUCCESS', username, {'username': username})
    return jsonify({'success': True}), 200

@app.route('/login', methods=['POST'])
def login():
    loginIP = request.remote_addr
    if not rateLimitChecker(loginIP):

        #loginIP stores IP to track later
        securityLogger.logEvent('SUSPICIOUS_ACTIVITY', None, {'reason': 'Rate limit exceeded', 'ip': loginIP}, 'WARNING')
        return jsonify({'error': 'Too many login attempts made, please wait a bit before attempting to login again.'}), 401

    data = request.get_json()
    username = data.get('username')
    if len(username) > 20:
        return jsonify({'error': 'Invalid username'}), 400

    password = data.get('password')

    users = getUsers()
    user = users.get(username, None)
    #check if username exists in user data
    if not user:
        #user_id = none, username doesn't exist
        securityLogger.logEvent('LOGIN_FAILED', None, {'username': username, 'reason': 'User does not exist'}, 'WARNING')
        return jsonify({'error': 'User does not exist.'}), 400
    #check if account has been locked
    if user.get('locked_until') and time.time() < user['locked_until']:
        securityLogger.logEvent('LOGIN_FAILED', username, {'reason': 'Account is locked'}, 'WARNING')
        return jsonify({'error': 'Account locked due to too many failed attempts, please try again later.'}), 401
    
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        user['failed_attempts'] += 1
        securityLogger.logEvent('LOGIN_FAILED', username, {'reason': 'Invalid password', 'failed_attempts': user['failed_attempts']}, 'WARNING')
        #lock user account until a specific time if this is their 5th failed attempt
        if user['failed_attempts'] >= 5:
            user['locked_until'] = time.time() + 900 
            securityLogger.logEvent('ACCOUNT_LOCKED', username, {'reason': '5 failed login attempts'}, 'ERROR')
        saveUsers(users)
        return jsonify({'error': 'Invalid credentials'}), 401
    user['failed_attempts'] = 0
    user['locked_until'] = None
    saveUsers(users)

    #delte old session
    old_token = request.cookies.get('session_token')
    if old_token:
        sessionManager.destroySession(old_token)

    token = sessionManager.createSession(user['username'])
    securityLogger.logEvent('SESSION_CREATED', username, {})
    securityLogger.logEvent('LOGIN_SUCCESS', username, {'username': username})

    response = jsonify({'success': True, 'role': user['role'], 'message': 'Successful login!'})
    
    response.set_cookie(
        'session_token',
        token,
        httponly=True,
        secure=False, ##not using https
        samesite='Strict',
        max_age=1800
    )
    return response, 200



@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_token')
    if token:
        sessionManager.destroySession(token)
        securityLogger.logEvent('SESSION_DESTROYED', g.user_id, {})
    response = jsonify({'success': True, 'message': 'Successful logout!'}), 200
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
            #GET requests don't have JSON try JSON first
            data = None
            if request.is_json:
                data = request.get_json(silent=True)

            docId = None

            #if JSON exists POST routes share/unshare
            if data and docArgName in data:
                docId = data.get(docArgName)

            #otherwise get docId from URL parameters GET /download/<docID>
            if not docId:
                docId = kwargs.get(docArgName)

            #if still missing, return error
            if not docId:
                return jsonify({"error": "Document ID missing"}), 400

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


# http --> https
"""
@app.before_request
def require_https():
    # skip HTTPS enforcement for static files
    if request.path.startswith('/static/'):
        return

    #only enforce HTTPS outside development
    if app.env != "development" and not request.is_secure:
        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=301)

"""


@app.before_request
def loadUserSession():
    if request.path.startswith('/static/'): #skip checking for ui files
        return
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
def uploadDocument():
    # check if file exists
    if 'file' not in request.files:
        return jsonify({'error': 'No file found'}), 404
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # sanitize filename --> prevent path traversal
    fileName = secure_filename(file.filename)
    if len(fileName) > 100:
        securityLogger.logEvent(
            'UPLOAD_BLOCKED',
            g.user_id,
            {'reason': 'Filename too long', 'fileName': fileName},
            'WARNING'
    )
    return jsonify({'error': 'Filename too long (max 100 characters)'}), 400


    # extension whitelist
    ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt'}
    _, ext = os.path.splitext(fileName.lower())

    if ext not in ALLOWED_EXTENSIONS:
        securityLogger.logEvent(
            'UPLOAD_BLOCKED',
            g.user_id,
            {'reason': 'Disallowed file type', 'fileName': fileName},
            'WARNING'
        )
        return jsonify({'error': 'File type not allowed'}), 400

    # MIME type validation
    ALLOWED_MIME_TYPES = {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain"
    }

    if file.mimetype not in ALLOWED_MIME_TYPES:
        securityLogger.logEvent(
            'UPLOAD_BLOCKED',
            g.user_id,
            {'reason': 'Invalid MIME type', 'mimetype': file.mimetype, 'fileName': fileName},
            'WARNING'
        )
        return jsonify({'error': 'Invalid file type (MIME mismatch)'}), 400
        # simple malware scan placeholder 
    file.seek(0)
    file_bytes = file.read()

    #  block files containing script tags
    if b"<script>" in file_bytes or b"<?php" in file_bytes:
        securityLogger.logEvent(
            'UPLOAD_BLOCKED',
            g.user_id,
            {'reason': 'Malware signature detected', 'fileName': fileName},
            'WARNING'
        )
        return jsonify({'error': 'File rejected due to unsafe content'}), 400

    #block empty files
    if len(file_bytes) == 0:
        securityLogger.logEvent(
            'UPLOAD_BLOCKED',
            g.user_id,
            {'reason': 'Empty file (possible malware)', 'fileName': fileName},
            'WARNING'
        )
        return jsonify({'error': 'Empty files are not allowed'}), 400

    # reset pointer for later encryption
    file.seek(0)


    # file size limit
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > MAX_FILE_SIZE:
        securityLogger.logEvent(
            'UPLOAD_BLOCKED',
            g.user_id,
            {'reason': 'File too large', 'size': size},
            'WARNING'
        )
        return jsonify({'error': 'File too large (max 10MB)'}), 400

    # create unique doc ID
    docID = str(uuid.uuid4())
    role = getCurrUserRole()

    # secure hashed file path
    filePath = documentManager.getSecureFilePath(docID, role)

    try:
        # encrypt file bytes and then upload
        encrypted_content = encryptedStorage.encryptDataBytes(file.read())

        with open(filePath, 'wb') as f:
            f.write(encrypted_content)

        # add metadata + versioning + audit log
        documentManager.createDocumentEntry(docID, g.user_id, fileName)
        documentManager.addVersion(docID, filePath, g.user_id)
        documentManager.logAction(docID, g.user_id, "UPLOAD")

        # security logging
        if role == 'admin':
            securityLogger.logEvent('ADMIN_UPLOAD_SUCCESS', g.user_id, {'docID': docID, 'fileName': fileName})
        else:
            securityLogger.logEvent('USER_UPLOAD_SUCCESS', g.user_id, {'docID': docID, 'fileName': fileName})

        # access logging
        accessLogger.logEvent("UPLOAD_SUCCESS", g.user_id, {"docID": docID, "fileName": fileName})

        return jsonify({'success': True, 'fileName': fileName}), 200

    except Exception as e:
        # error logging
        if role == 'admin':
            securityLogger.logEvent('ADMIN_UPLOAD_FAILURE', g.user_id, {'error': str(e)}, 'ERROR')
        else:
            securityLogger.logEvent('USER_UPLOAD_FAILURE', g.user_id, {'error': str(e)}, 'ERROR')

        return jsonify({'success': False, 'error': 'Upload failed'}), 500

    

    
    
@app.route('/download/<docID>', methods=['GET'])
@requireAuthentication
@requireRole(ROLE_ADMIN, ROLE_USER, ROLE_GUEST)
@requireDocumentPermission("docID", "viewer")
def downloadDocument(docID):
    metadata = documentManager.loadMetadata()
    doc = metadata.get(docID)
    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    currUser = g.user_id
    role = getCurrUserRole()

    #check whether current user has access
    userHasAccess = role == 'admin' or doc['owner'] == currUser or currUser in doc['sharedWith']
    if not userHasAccess:
        securityLogger.logEvent('UNAUTHORIZED_ACCESS', currUser, {'docID': docID}, 'CRITICAL')
        return jsonify({'error': 'Access denied.'}), 403

    try:
        #get path from metadata which was generated by getFilePath during upload
        filePath = doc['versions'][-1]['path']
        
        with open(filePath, 'rb') as f:
            encryptedData = f.read()
        decryptedData = encryptedStorage.decryptDataBytes(encryptedData)
        documentManager.logAction(docID, currUser, "DOWNLOAD")
        securityLogger.logEvent('DOWNLOAD_SUCCESS', currUser, {'docID': docID})

        #file to send to browser w/ original general file name
        accessLogger.logEvent("DOWNLOAD_SUCCESS", currUser, {"docID": docID})
        return send_file(io.BytesIO(decryptedData), download_name=doc['fileName'], as_attachment=True)

    except Exception as e:
        securityLogger.logEvent('DOWNLOAD_ERROR', currUser, {'error': str(e)}, 'ERROR')
        return jsonify({'success': False, 'error': 'Could not process download.'}), 500


@app.route('/share', methods=['POST'])
@requireAuthentication
def shareDocument():
    #allows owner + admin to share a doc
    #adds users as either editor or viewer
    user = getCurrUser()  # current logged-in user
    data = request.get_json()

    docId = data.get("docId")
    targetUser = data.get("targetUser")
    if len(targetUser) > 20:
        return jsonify({"error": "Target username too long"}), 400

    role = data.get("role")  # view or editor

    #validate role input
    if role not in ["viewer", "editor"]:
        return jsonify({"error": "Invalid role"}), 400

    # does target exisr
    users = getUsers()
    if targetUser not in users:
        return jsonify({"error": "Target user does not exist"}), 400

    # cant self share
    if targetUser == user["username"]:
        return jsonify({"error": "You cannot share a document with yourself."}), 400

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

    # no dupe sharing
    if targetUser in docMeta.get("sharedWith", {}):
        return jsonify({"error": "User already has access to this document."}), 400

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

    accessLogger.logEvent("SHARE_SUCCESS", user["username"], {"docID": docId, "targetUser": targetUser, "role": role})

    return jsonify({"success": True, "message": f"Document shared with {targetUser} as {role}."}), 200

@app.route('/unshare', methods=['POST'])
@requireAuthentication
def unshareDocument():
    #remove access to document
    user = getCurrUser()
    data = request.get_json()

    docId = data.get("docId")
    targetUser = data.get("targetUser")
    if len(targetUser) > 20:
        return jsonify({"error": "Target username too long"}), 400


    # target exists
    users = getUsers()
    if targetUser not in users:
        return jsonify({"error": "Target user does not exist"}), 400

    # cant unshare self
    if targetUser == user["username"]:
        return jsonify({"error": "You cannot unshare a document from yourself."}), 400

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

    # dont unshare someone who doesnt have access
    if targetUser not in docMeta.get("sharedWith", {}):
        return jsonify({"error": "User does not currently have access to this document."}), 400

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

    accessLogger.logEvent("UNSHARE_SUCCESS", user["username"], {"docID": docId, "targetUser": targetUser})


    return jsonify({"success": True, "message": f"{targetUser} no longer has access."}), 200

#view audit log for doc
@app.route('/document/<docId>/audit', methods=['GET'])
@requireAuthentication
@requireDocumentPermission("docId", "owner")   # must at least be able to view the document
def getDocumentAudit(docId):
    # load metadata
    docMeta = getDocument(docId)
    if not docMeta:
        return jsonify({"error": "Document not found"}), 404

    # log access to audit trail
    documentManager.logAction(docId, g.user_id, "VIEW_AUDIT_TRAIL")
    securityLogger.logEvent(
        "DATA_ACCESS",
        g.user_id,
        {"resource": docId, "action": "view_audit_trail"}
    )

    accessLogger.logEvent("VIEW_AUDIT_LOG", g.user_id, {"docID": docId})


    # return audit log + version history
    return jsonify({
        "docId": docId,
        "fileName": docMeta.get("fileName"),
        "owner": docMeta.get("owner"),
        "createdAt": docMeta.get("createdAt"),
        "versions": docMeta.get("versions", []),
        "auditLog": docMeta.get("auditLog", []),
        "sharedWith": docMeta.get("sharedWith", {})
    }), 200


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

    return jsonify({"success": True, "message": f"{username} has been downgraded to guest."}), 200

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

    return jsonify({"success": True, "message": f"{username} has been upgraded to {newRole}."}), 200

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

    accessLogger.logEvent("VIEW_FILE_LIST", g.user_id, {})

    return jsonify(visibleFiles), 200

@app.route('/findUsersList', methods=['GET'])
@requireAuthentication
@requireRole(ROLE_ADMIN)
def findUsersList():
    users = getUsers()
    usersList = []
    for username, data in users.items():
        usersList.append({
            'username': username,
            'email': data.get('email', 'N/A'),
            'role': data.get('role', 'guest'),
            'status': 'Locked' if data.get('locked_until') and time.time() < data['locked_until'] else 'Active'     #account locked status
        })

    accessLogger.logEvent("VIEW_USERS_LIST", g.user_id, {})
    
    return jsonify(usersList), 200

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/deleteDocument', methods=['POST'])
@requireAuthentication
def deleteDocument():
    # delete a document (owner or admin only)
    user = getCurrUser()
    data = request.get_json()

    docId = data.get("docId")
    docMeta = getDocument(docId)

    # check if doc exists
    if not docMeta:
        return jsonify({"error": "Document not found"}), 404

    # only owner or admin can delete
    if getCurrUserRole() != ROLE_ADMIN and not isOwner(user["username"], docMeta):
        securityLogger.logEvent(
            "ACCESS_DENIED",
            user["username"],
            {"resource": docId, "reason": "Only owner/admin can delete"},
            "WARNING"
        )
        return jsonify({"error": "You do not have permission to delete this document."}), 403

    # delete encrypted file
    try:
        for version in docMeta.get("versions", []):
            filePath = version.get("path")
            if filePath and os.path.exists(filePath):
                os.remove(filePath)
    except Exception as e:
        securityLogger.logEvent(
            "DELETE_ERROR",
            user["username"],
            {"resource": docId, "error": str(e)},
            "ERROR"
        )
        return jsonify({"error": "Failed to delete file from storage."}), 500

    # remove metadata entry
    metadata = documentManager.loadMetadata()
    if docId in metadata:
        del metadata[docId]
        documentManager.saveMetadata(metadata)

    # log to audit log
    documentManager.logAction(docId, user["username"], "DELETE")

    # log to security log
    securityLogger.logEvent(
        "DATA_ACCESS",
        user["username"],
        {"resource": docId, "action": "delete"}
    )

    accessLogger.logEvent("DELETE_SUCCESS", user["username"], {"docID": docId})
    return jsonify({"success": True, "message": "Document deleted successfully."}), 200


@app.route('/dashboard')
@requireAuthentication
def dashboard():
    return render_template('dashboard.html')



@app.route('/changePassword', methods=['POST'])
@requireAuthentication
def change_password():
    data = request.get_json()
    old_password = data.get("oldPassword")
    new_password = data.get("newPassword")

    username = g.user_id
    users = getUsers()
    user = users.get(username)

    # user missing
    if not user:
        securityLogger.logEvent(
            "PASSWORD_CHANGE_FAILED",
            username,
            {"reason": "User not found"},
            "ERROR"
        )
        return jsonify({"error": "User not found"}), 404

    # verify old password
    if not bcrypt.checkpw(old_password.encode(), user["password_hash"].encode()):
        securityLogger.logEvent(
            "PASSWORD_CHANGE_FAILED",
            username,
            {"reason": "Incorrect old password"},
            "WARNING"
        )
        return jsonify({"error": "Incorrect current password"}), 400

    # validate new password
    if not validatePassword(new_password):
        securityLogger.logEvent(
            "PASSWORD_CHANGE_FAILED",
            username,
            {"reason": "Weak password"},
            "WARNING"
        )
        return jsonify({"error": "Password does not meet requirements"}), 400

    # hash password
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(12)).decode()
    user["password_hash"] = new_hash

    
    saveUsers(users)

    # log success
    securityLogger.logEvent(
        "PASSWORD_CHANGED",
        username,
        {"message": "Password updated successfully"}
    )

    return jsonify({"success": True, "message": "Password updated successfully"}), 200




if __name__ == '__main__':
    #generate cert.pem/key.pem as in the spec:
    # openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    app.run(
        #ssl_context=('cert.pem', 'key.pem'),
        host='0.0.0.0',
        port=5000,
        debug=False
    )
