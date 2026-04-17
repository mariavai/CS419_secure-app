import logging
import json
from datetime import datetime
import os
from flask import request, has_request_context
import secrets
import time
from cryptography.fernet import Fernet
import hashlib


class EncryptedStorage:
    def __init__(self, key_file='secret.key'):
        try:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def saveEncrypted(self, filename, data):
        """Save encrypted JSON data"""
        json_data = json.dumps(data)
        encrypted = self.cipher.encrypt(json_data.encode())
        
        with open(filename, 'wb') as f:
            f.write(encrypted)

    def loadEncrypted(self, filename):
        """Load and decrypt JSON data"""
        with open(filename, 'rb') as f:
            encrypted = f.read()
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())
    
    def encryptDataBytes(self, data):
        return self.cipher.encrypt(data)

    def decryptDataBytes(self, data):
        return self.cipher.decrypt(data) 
    
    

class SessionManager:
    def __init__(self, timeout=1800): #30 minutes
        if not os.path.exists('data'):  #create data directory if it doesnt exist
            os.makedirs('data')
        self.timeout = timeout
        self.sessions_file = 'data/sessions.json'
        
    def createSession(self, user_id):
        """Create new session token"""
        token = secrets.token_urlsafe(32)
        ip = None
        userAgent = None
        if has_request_context():
            ip = request.remote_addr
            userAgent = request.headers.get('User-Agent')
        session = {
            'token': token,
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': ip,
            'user_agent': userAgent
        }
        
        #save session
        sessions = self.loadSessions()
        sessions[token] = session
        self.saveSessions(sessions)
        return token
    
    def validateSession(self, token):
        """Check if session is valid"""
        sessions = self.loadSessions()
        if token not in sessions:
            return None
            
        session = sessions[token]
        
        #check timeout
        if time.time() - session['last_activity'] > self.timeout:
            self.destroySession(token)
            return None
            
        #update last activity
        session['last_activity'] = time.time()
        sessions[token] = session
        self.saveSessions(sessions)
        return session
    
    def destroySession(self, token):
        """Delete session"""
        sessions = self.loadSessions()
        if token in sessions:
            del sessions[token]
            self.saveSessions(sessions)


    def loadSessions(self):
        with open(self.sessions_file, 'r') as f:
            return json.load(f)
    

    def saveSessions(self, sessions):
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f, indent=4)

    
    
            
            
            

class SecurityLogger:
    def __init__(self, log_file='logs/security.log'):
        if not os.path.exists('logs'):  #create logs directory if it doesnt exist
            os.makedirs('logs')
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def logEvent(self, event_type, user_id, details, severity='INFO'):
        """Log security event"""
        
        ip = None
        userAgent = None
        if has_request_context():
            ip = request.remote_addr
            userAgent = request.headers.get('User-Agent')

        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': userAgent,
            'details': details,
            'severity': severity
        }
        
        if severity == 'CRITICAL':
            self.logger.critical(json.dumps(log_entry))
        elif severity == 'ERROR':
            self.logger.error(json.dumps(log_entry))
        elif severity == 'WARNING':
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))


class DocumentManager:
    
    def __init__(self, metadataFile='data/documents.json', USER_FOLDER_PATH = 'data/files/users', ADMIN_FOLDER_PATH = 'data/files/admin'):
        # path to metadata file
        self.metadataFile = metadataFile
        self.USER_FOLDER_PATH = USER_FOLDER_PATH
        self.ADMIN_FOLDER_PATH = ADMIN_FOLDER_PATH
        self.FILE_PATH_PEPPER = "PEPPERsecure284920370472375"

        # ensure all relevant data dirs exists
        if not os.path.exists('data'):
            os.makedirs('data')
        if not os.path.exists('data/files'):
            os.makedirs('data/files')
        if not os.path.exists(self.USER_FOLDER_PATH):
            os.makedirs(self.USER_FOLDER_PATH)
        if not os.path.exists(self.ADMIN_FOLDER_PATH):
            os.makedirs(self.ADMIN_FOLDER_PATH)

        # ensure metadata file exists
        if not os.path.exists(self.metadataFile):
            with open(self.metadataFile, 'w') as f:
                json.dump({}, f)

    def loadMetadata(self):
        #loads documents from json to python
        with open(self.metadataFile, 'r') as f:
            return json.load(f)

    def saveMetadata(self, data):
        #saves metadata back into json 
        with open(self.metadataFile, 'w') as f:
            json.dump(data, f, indent=4)
            
    def getSecureFilePath(self, docID, role):
        #combining docID with pepper and hashing it so filePath is not guessable
        filenameHash = hashlib.sha256((docID + self.FILE_PATH_PEPPER).encode()).hexdigest()
        #set filePath depending on whether they are a user or admin
        folderPath = self.USER_FOLDER_PATH
        if role == 'admin':
            folderPath = self.ADMIN_FOLDER_PATH
        return os.path.join(folderPath, filenameHash)
    

    def createDocumentEntry(self, docId, owner, fileName):
        #creates new document with default data
        metadata = self.loadMetadata()

        metadata[docId] = {
            "owner": owner,
            "fileName": fileName,
            "createdAt": time.time(),
            "versions": [],
            "sharedWith": {},
            "auditLog": []
        }

        self.saveMetadata(metadata)

    def addVersion(self, docId, versionPath, uploadedBy):
        #new version encyrpted
        metadata = self.loadMetadata()
        doc = metadata.get(docId)

        if not doc:
            return False

        versionNumber = len(doc["versions"]) + 1

        doc["versions"].append({
            "version": versionNumber,
            "path": versionPath,
            "timestamp": time.time(),
            "uploadedBy": uploadedBy
        })

        self.saveMetadata(metadata)
        return True

    def shareDocument(self, docId, targetUser, role):
        #share document and assign role: reader editor etc
        metadata = self.loadMetadata()
        doc = metadata.get(docId)

        if not doc:
            return False

        doc["sharedWith"][targetUser] = role
        self.saveMetadata(metadata)
        return True

    def unshareDocument(self, docId, targetUser):
        #remove access to document
        metadata = self.loadMetadata()
        doc = metadata.get(docId)

        if not doc:
            return False

        if targetUser in doc["sharedWith"]:
            del doc["sharedWith"][targetUser]
            self.saveMetadata(metadata)
            return True

        return False

    def logAction(self, docId, user, action):
        #audit log
        metadata = self.loadMetadata()
        doc = metadata.get(docId)

        if not doc:
            return False

        doc["auditLog"].append({
            "timestamp": time.time(),
            "user": user,
            "action": action
        })

        self.saveMetadata(metadata)
        return True
