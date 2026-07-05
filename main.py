import os
import json
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import firebase_admin
from firebase_admin import credentials, auth, firestore

# ---- Firebase init ----
service_account_json = os.environ.get('FIREBASE_SERVICE_ACCOUNT')
if service_account_json:
    service_account_info = json.loads(service_account_json)
    cred = credentials.Certificate(service_account_info)
else:
    cred = credentials.Certificate(r"C:\Users\reece\Downloads\serviceaccount.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

OWNER_UID = os.environ.get('OWNER_UID', '')
STEAM_KEY = os.environ.get('STEAM_KEY', '')
PORT = int(os.environ.get('PORT', 3000))


def fetch_url(url):
    try:
        with urllib.request.urlopen(url) as r:
            return r.read().decode()
    except Exception:
        return None


def get_token(handler):
    auth_header = handler.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    if not token:
        return None
    try:
        return auth.verify_id_token(token)
    except Exception:
        return None


def get_user(uid):
    doc = db.collection('users').document(uid).get()
    if doc.exists:
        data = doc.to_dict()
        data['uid'] = uid
        return data
    return None


def is_admin(uid):
    user = get_user(uid)
    return user and user.get('role') in ['admin', 'owner']


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def send_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization,Content-Type')

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_cors()
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]

        if path == '/api/version':
            return self.send_json(200, {'version': '0.1.0'})

        if path == '/api/me':
            decoded = get_token(self)
            if not decoded:
                return self.send_json(401, {'error': 'Not logged in.'})
            user = get_user(decoded['uid'])
            if not user:
                return self.send_json(404, {'error': 'User not found.'})
            if user.get('banned'):
                return self.send_json(403, {'error': 'Account banned.'})
            return self.send_json(200, {
                'uid': decoded['uid'],
                'username': user.get('username', ''),
                'email': user.get('email', ''),
                'since': user.get('since', ''),
                'role': user.get('role', 'user'),
                'emailVerified': decoded.get('email_verified', False) or user.get('emailVerified', False),
                'steamOk': user.get('steamOk', False),
                'wotOk': user.get('wotOk', False),
                'isAdmin': user.get('role') in ['admin', 'owner'],
                'isOwner': user.get('role') == 'owner'
            })

        if path == '/api/posts':
            docs = db.collection('posts').order_by(
                'createdAt', direction=firestore.Query.DESCENDING
            ).stream()
            posts = []
            for doc in docs:
                d = doc.to_dict()
                d['id'] = doc.id
                if 'createdAt' in d and hasattr(d['createdAt'], 'isoformat'):
                    d['createdAt'] = d['createdAt'].isoformat()
                posts.append(d)
            return self.send_json(200, posts)

        if path == '/api/admin/users':
            decoded = get_token(self)
            if not decoded or not is_admin(decoded['uid']):
                return self.send_json(403, {'error': 'Admins only.'})
            docs = db.collection('users').stream()
            users = []
            for doc in docs:
                d = doc.to_dict()
                d['uid'] = doc.id
                if 'createdAt' in d and hasattr(d['createdAt'], 'isoformat'):
                    d['createdAt'] = d['createdAt'].isoformat()
                users.append(d)
            return self.send_json(200, users)

        if path == '/api/admin/stats':
            decoded = get_token(self)
            if not decoded or not is_admin(decoded['uid']):
                return self.send_json(403, {'error': 'Admins only.'})
            users = list(db.collection('users').stream())
            posts = list(db.collection('posts').stream())
            all_users = [u.to_dict() for u in users]
            return self.send_json(200, {
                'totalUsers': len(all_users),
                'verifiedUsers': sum(1 for u in all_users if u.get('emailVerified')),
                'bannedUsers': sum(1 for u in all_users if u.get('banned')),
                'totalPosts': len(posts),
                'totalAdmins': sum(1 for u in all_users if u.get('role') in ['admin', 'owner'])
            })

        self.send_json(404, {'error': 'Not found.'})

    def do_POST(self):
        path = self.path.split('?')[0]
        body = self.read_body()

        if path == '/api/register':
            email = body.get('email', '').strip()
            password = body.get('password', '').strip()
            username = body.get('username', '').strip()
            if not email or not password or not username:
                return self.send_json(400, {'error': 'Missing fields.'})
            try:
                existing = db.collection('users').where('username', '==', username).stream()
                if any(True for _ in existing):
                    return self.send_json(400, {'error': 'Username already taken.'})
                user = auth.create_user(email=email, password=password, display_name=username)
                role = 'owner' if user.uid == OWNER_UID else 'user'
                from datetime import datetime
                since = datetime.now().strftime('%b %Y')
                db.collection('users').document(user.uid).set({
                    'email': email,
                    'username': username,
                    'since': since,
                    'role': role,
                    'emailVerified': False,
                    'steamOk': False,
                    'wotOk': False,
                    'banned': False,
                    'createdAt': firestore.SERVER_TIMESTAMP
                })
                custom_token = auth.create_custom_token(user.uid)
                return self.send_json(200, {
                    'customToken': custom_token.decode(),
                    'username': username,
                    'since': since,
                    'role': role
                })
            except Exception as e:
                return self.send_json(400, {'error': str(e)})

        if path == '/api/verifyEmail':
            decoded = get_token(self)
            if not decoded:
                return self.send_json(401, {'error': 'Not logged in.'})
            db.collection('users').document(decoded['uid']).update({'emailVerified': True})
            return self.send_json(200, {'ok': True})

        if path == '/api/verifySteam':
            decoded = get_token(self)
            if not decoded:
                return self.send_json(401, {'error': 'Not logged in.'})
            steam_id = body.get('steamId', '')
            if not steam_id.isdigit() or len(steam_id) != 17:
                return self.send_json(400, {'error': 'Invalid Steam ID.'})
            if not STEAM_KEY:
                return self.send_json(500, {'error': 'Steam API key not configured.'})
            url = f'https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/?key={STEAM_KEY}&steamid={steam_id}&include_appinfo=false&format=json'
            data = fetch_url(url)
            if not data:
                return self.send_json(500, {'error': 'Could not reach Steam.'})
            try:
                parsed = json.loads(data)
                games = parsed.get('response', {}).get('games', [])
                ets2 = next((g for g in games if g['appid'] == 227300), None)
                hours = ets2['playtime_forever'] / 60 if ets2 else 0
                if hours < 72:
                    return self.send_json(400, {'error': f'Only {int(hours)}h found. Need 72h in ETS2.'})
                db.collection('users').document(decoded['uid']).update({
                    'steamOk': True,
                    'steamId': steam_id,
                    'steamHours': int(hours)
                })
                return self.send_json(200, {'ok': True, 'hours': int(hours)})
            except Exception:
                return self.send_json(500, {'error': 'Steam check failed.'})

        if path == '/api/verifyWot':
            decoded = get_token(self)
            if not decoded:
                return self.send_json(401, {'error': 'Not logged in.'})
            wot_name = body.get('wotName', '')
            encoded = urllib.parse.quote(wot_name)
            data = fetch_url(f'https://www.worldoftrucks.com/en/online_driver.php?nick={encoded}')
            if not data or wot_name not in data:
                return self.send_json(400, {'error': 'Driver not found on World of Trucks.'})
            db.collection('users').document(decoded['uid']).update({'wotOk': True, 'wotName': wot_name})
            return self.send_json(200, {'ok': True})

        if path == '/api/posts':
            decoded = get_token(self)
            if not decoded or not is_admin(decoded['uid']):
                return self.send_json(403, {'error': 'Admins only.'})
            title = body.get('title', '').strip()
            body_text = body.get('body', '').strip()
            if not title or not body_text:
                return self.send_json(400, {'error': 'Title and body required.'})
            from datetime import datetime
            doc_ref = db.collection('posts').document()
            doc_ref.set({
                'title': title,
                'tag': body.get('tag', 'Update'),
                'body': body_text,
                'thumb': body.get('thumb', ''),
                'video': body.get('video', ''),
                'author': decoded['uid'],
                'date': datetime.now().strftime('%b %d, %Y'),
                'createdAt': firestore.SERVER_TIMESTAMP
            })
            return self.send_json(200, {'id': doc_ref.id})

        if path == '/api/admin/ban':
            decoded = get_token(self)
            if not decoded or not is_admin(decoded['uid']):
                return self.send_json(403, {'error': 'Admins only.'})
            uid = body.get('uid', '')
            ban = body.get('ban', True)
            target = get_user(uid)
            if not target:
                return self.send_json(404, {'error': 'User not found.'})
            if target.get('role') == 'owner':
                return self.send_json(403, {'error': 'Cannot ban owner.'})
            db.collection('users').document(uid).update({'banned': ban})
            auth.update_user(uid, disabled=ban)
            return self.send_json(200, {'ok': True})

        if path == '/api/admin/promote':
            decoded = get_token(self)
            if not decoded:
                return self.send_json(401, {'error': 'Not logged in.'})
            caller = get_user(decoded['uid'])
            if not caller or caller.get('role') != 'owner':
                return self.send_json(403, {'error': 'Owner only.'})
            uid = body.get('uid', '')
            promote = body.get('promote', False)
            db.collection('users').document(uid).update({
                'role': 'admin' if promote else 'user'
            })
            return self.send_json(200, {'ok': True})

        self.send_json(404, {'error': 'Not found.'})

    def do_DELETE(self):
        path = self.path.split('?')[0]
        body = self.read_body()

        if path == '/api/posts':
            decoded = get_token(self)
            if not decoded or not is_admin(decoded['uid']):
                return self.send_json(403, {'error': 'Admins only.'})
            post_id = body.get('postId', '')
            db.collection('posts').document(post_id).delete()
            return self.send_json(200, {'ok': True})

        self.send_json(404, {'error': 'Not found.'})


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    print(f'Convoy backend running on port {PORT}')
    server.serve_forever()
