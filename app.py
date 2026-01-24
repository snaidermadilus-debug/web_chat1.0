import sqlite3
import os
import secrets
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import re
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.expanduser("~/.cache/.chatdata/.x9a_final.db")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='threading',
                   ping_timeout=60,
                   ping_interval=25,
                   transports=['polling'])

# Estruturas em memória
connected_users = {}        # {grupo_id: {sid: (usuario, session_token, device_id)}}
temp_tokens = {}            # {token: (grupo_id, usuario, expires, device_id)}
failed_attempts = {}        # {ip: (count, reset_time)}

# Constantes
INACTIVITY_TIMEOUT = 10  # minutos

def init_db():
    """Inicializa o banco de dados"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS grupos (
            grupo_uuid TEXT PRIMARY KEY,
            grupo_id TEXT UNIQUE NOT NULL,
            criado_em TEXT NOT NULL,
            criado_por TEXT NOT NULL,
            senha_hash TEXT,
            privado BOOLEAN DEFAULT 0
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grupo_uuid TEXT NOT NULL,
            usuario TEXT NOT NULL,
            mensagem TEXT NOT NULL,
            data_hora TEXT NOT NULL,
            FOREIGN KEY (grupo_uuid) REFERENCES grupos(grupo_uuid) ON DELETE CASCADE
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessoes (
            session_token TEXT PRIMARY KEY,
            grupo_uuid TEXT NOT NULL,
            usuario TEXT NOT NULL,
            device_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(grupo_uuid, usuario, device_id)
        )
    ''')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_user_device ON sessoes(grupo_uuid, usuario, device_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_last_seen ON sessoes(last_seen)')
    
    conn.execute('PRAGMA foreign_keys = ON')
    conn.commit()
    conn.close()
    
    print("✅ Banco de dados OK")

def hash_password(password):
    """Gera hash para senha"""
    if not password:
        return None
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password, hashed):
    """Verifica senha"""
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

def generate_token():
    """Gera token de 6 dígitos"""
    return ''.join(secrets.choice('0123456789') for _ in range(6))

def sanitize_input(text, max_length=500):
    """Sanitiza input"""
    if not text:
        return ""
    
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    text = re.sub(r'[\x00-\x1F\x7F]', '', text)
    
    return text

def check_rate_limit(ip):
    """Verifica limite de tentativas"""
    now = datetime.now()
    
    if ip not in failed_attempts:
        failed_attempts[ip] = [0, now]
    
    count, reset_time = failed_attempts[ip]
    
    if now > reset_time + timedelta(minutes=15):
        failed_attempts[ip] = [0, now]
        return True
    
    if count >= 10:
        return False
    
    return True

def increment_failed_attempt(ip):
    """Incrementa tentativas falhas"""
    if ip not in failed_attempts:
        failed_attempts[ip] = [0, datetime.now()]
    failed_attempts[ip][0] += 1

def validate_session(session_token, grupo_id, device_id):
    """Valida sessão"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''SELECT s.usuario 
                 FROM sessoes s
                 JOIN grupos g ON s.grupo_uuid = g.grupo_uuid
                 WHERE s.session_token = ? AND g.grupo_id = ? AND s.device_id = ?
                 AND s.expires_at > ?''',
              (session_token, grupo_id, device_id, datetime.now().isoformat()))
    result = c.fetchone()
    
    if result:
        c.execute('UPDATE sessoes SET last_seen = ? WHERE session_token = ?',
                  (datetime.now().isoformat(), session_token))
        conn.commit()
    
    conn.close()
    
    return result[0] if result else None

def is_username_taken_by_other_device(grupo_uuid, usuario, device_id):
    """Verifica se nome está em uso por OUTRO dispositivo"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''SELECT COUNT(*) FROM sessoes 
                 WHERE grupo_uuid = ? AND usuario = ? AND device_id != ? 
                 AND expires_at > ?''',
              (grupo_uuid, usuario, device_id, datetime.now().isoformat()))
    
    count = c.fetchone()[0]
    conn.close()
    
    return count > 0

def cleanup_inactive_users():
    """Remove usuários inativos"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        timeout = (datetime.now() - timedelta(minutes=INACTIVITY_TIMEOUT)).isoformat()
        c.execute('DELETE FROM sessoes WHERE last_seen < ?', (timeout,))
        
        removed = c.rowcount
        if removed > 0:
            print(f"🧹 Removidos {removed} usuários inativos")
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Erro na limpeza: {e}")

def get_local_ip():
    """Obtém IP local"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# Inicializa
init_db()
cleanup_inactive_users()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

@socketio.on('connect')
def handle_connect():
    print(f"✅ Cliente conectado: {request.remote_addr}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    
    for grupo_id in list(connected_users.keys()):
        if sid in connected_users[grupo_id]:
            usuario = connected_users[grupo_id][sid][0]
            del connected_users[grupo_id][sid]
            
            if not connected_users[grupo_id]:
                del connected_users[grupo_id]
            
            current_count = len(connected_users.get(grupo_id, {}))
            emit('user_count_update', {'grupo_id': grupo_id, 'count': current_count}, broadcast=True)
            break

@socketio.on('create_group')
def handle_create_group(data):
    ip = request.remote_addr
    
    if not check_rate_limit(ip):
        emit('group_result', {'success': False, 'msg': 'Aguarde 15 minutos'})
        return
    
    grupo_id = sanitize_input(data.get('grupo_id', ''), 10)
    usuario = sanitize_input(data.get('usuario', ''), 15)
    password = data.get('password', '').strip()
    is_private = data.get('private', False)
    device_id = data.get('device_id', '').strip()
    
    if not device_id:
        emit('group_result', {'success': False, 'msg': 'Device ID necessário'})
        return
    
    if not grupo_id or not usuario:
        emit('group_result', {'success': False, 'msg': 'Dados inválidos'})
        return
    
    if not re.match(r'^[a-zA-Z0-9_-]{1,10}$', grupo_id):
        emit('group_result', {'success': False, 'msg': 'ID inválido'})
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT grupo_uuid FROM grupos WHERE grupo_id = ?', (grupo_id,))
    if c.fetchone():
        emit('group_result', {'success': False, 'msg': 'Grupo já existe'})
        conn.close()
        return
    
    grupo_uuid = str(uuid.uuid4())
    senha_hash = hash_password(password) if is_private else None
    
    c.execute('''INSERT INTO grupos (grupo_uuid, grupo_id, criado_em, criado_por, senha_hash, privado)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (grupo_uuid, grupo_id, datetime.now().isoformat(), usuario, senha_hash, 1 if is_private else 0))
    
    session_token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
    last_seen = datetime.now().isoformat()
    
    c.execute('''INSERT INTO sessoes (session_token, grupo_uuid, usuario, device_id, expires_at, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (session_token, grupo_uuid, usuario, device_id, expires_at, last_seen))
    
    conn.commit()
    conn.close()
    
    if grupo_id not in connected_users:
        connected_users[grupo_id] = {}
    connected_users[grupo_id][request.sid] = (usuario, session_token, device_id)
    
    emit('group_result', {
        'success': True,
        'grupo_id': grupo_id,
        'usuario': usuario,
        'session_token': session_token,
        'device_id': device_id,
        'historico': [],
        'user_count': 1,
        'is_private': is_private,
        'is_admin': True
    })
    
    emit('user_count_update', {'grupo_id': grupo_id, 'count': 1}, broadcast=True)

@socketio.on('join_group')
def handle_join_group(data):
    ip = request.remote_addr
    
    grupo_id = sanitize_input(data.get('grupo_id', ''), 10)
    usuario = sanitize_input(data.get('usuario', ''), 15)
    password = data.get('password', '').strip()
    session_token = data.get('session_token', '').strip()
    device_id = data.get('device_id', '').strip()
    
    if not device_id:
        emit('group_result', {'success': False, 'msg': 'Device ID necessário'})
        return
    
    if not grupo_id or not usuario:
        emit('group_result', {'success': False, 'msg': 'Dados inválidos'})
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT grupo_uuid, privado, senha_hash FROM grupos WHERE grupo_id = ?', (grupo_id,))
    grupo_info = c.fetchone()
    
    if not grupo_info:
        emit('group_result', {'success': False, 'msg': 'Grupo não encontrado'})
        conn.close()
        return
    
    grupo_uuid, is_private, senha_hash = grupo_info
    
    if is_username_taken_by_other_device(grupo_uuid, usuario, device_id):
        emit('group_result', {
            'success': False, 
            'msg': f'O nome "{usuario}" já está em uso por outro dispositivo'
        })
        conn.close()
        return
    
    if is_private:
        if not password:
            emit('group_result', {'success': False, 'msg': 'Senha necessária'})
            conn.close()
            return
        
        if not verify_password(password, senha_hash):
            emit('group_result', {'success': False, 'msg': 'Senha incorreta'})
            conn.close()
            return
    
    valid_usuario = None
    if session_token:
        valid_usuario = validate_session(session_token, grupo_id, device_id)
    
    if not valid_usuario or valid_usuario != usuario:
        c.execute('DELETE FROM sessoes WHERE grupo_uuid = ? AND usuario = ? AND device_id = ?',
                  (grupo_uuid, usuario, device_id))
        
        session_token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        last_seen = datetime.now().isoformat()
        
        c.execute('''INSERT INTO sessoes (session_token, grupo_uuid, usuario, device_id, expires_at, last_seen)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (session_token, grupo_uuid, usuario, device_id, expires_at, last_seen))
    else:
        c.execute('UPDATE sessoes SET last_seen = ? WHERE session_token = ?',
                  (datetime.now().isoformat(), session_token))
    
    c.execute('''SELECT usuario, mensagem, data_hora 
                 FROM mensagens 
                 WHERE grupo_uuid = ? 
                 ORDER BY data_hora ASC 
                 LIMIT 100''', (grupo_uuid,))
    historico = [{'user': r[0], 'msg': r[1], 'time': r[2]} for r in c.fetchall()]
    
    conn.commit()
    conn.close()
    
    if grupo_id not in connected_users:
        connected_users[grupo_id] = {}
    
    sids_to_remove = []
    for sid, (existing_user, _, existing_device) in connected_users[grupo_id].items():
        if existing_user == usuario and existing_device == device_id:
            sids_to_remove.append(sid)
    
    for sid in sids_to_remove:
        del connected_users[grupo_id][sid]
    
    connected_users[grupo_id][request.sid] = (usuario, session_token, device_id)
    
    current_count = len(connected_users[grupo_id])
    
    emit('group_result', {
        'success': True,
        'grupo_id': grupo_id,
        'usuario': usuario,
        'session_token': session_token,
        'device_id': device_id,
        'historico': historico,
        'user_count': current_count,
        'is_private': bool(is_private),
        'message': '✅ Conectado!'
    })
    
    emit('user_count_update', {'grupo_id': grupo_id, 'count': current_count}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    grupo_id = data.get('grupo_id', '').strip()
    usuario = data.get('usuario', '').strip()
    session_token = data.get('session_token', '').strip()
    device_id = data.get('device_id', '').strip()
    msg = data.get('msg', '').strip()
    
    if not all([grupo_id, usuario, session_token, device_id, msg]) or len(msg) > 500:
        return
    
    valid_usuario = validate_session(session_token, grupo_id, device_id)
    if not valid_usuario or valid_usuario != usuario:
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT grupo_uuid FROM grupos WHERE grupo_id = ?', (grupo_id,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        return
    
    grupo_uuid = result[0]
    
    msg = sanitize_input(msg, 500)
    data_hora = datetime.now().isoformat()
    
    c.execute('INSERT INTO mensagens (grupo_uuid, usuario, mensagem, data_hora) VALUES (?, ?, ?, ?)',
              (grupo_uuid, usuario, msg, data_hora))
    
    conn.commit()
    conn.close()
    
    emit('receive_message', {
        'grupo_id': grupo_id,
        'usuario': usuario,
        'msg': msg,
        'timestamp': data_hora
    }, broadcast=True)

@socketio.on('leave_group')
def handle_leave_group(data):
    sid = request.sid
    grupo_id = data.get('grupo_id', '')
    session_token = data.get('session_token', '')
    device_id = data.get('device_id', '')
    
    if grupo_id in connected_users and sid in connected_users[grupo_id]:
        usuario = connected_users[grupo_id][sid][0]
        
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('DELETE FROM sessoes WHERE session_token = ? AND device_id = ?',
                      (session_token, device_id))
            conn.commit()
            conn.close()
        except:
            pass
        
        del connected_users[grupo_id][sid]
        
        if not connected_users[grupo_id]:
            del connected_users[grupo_id]
        
        current_count = len(connected_users.get(grupo_id, {}))
        emit('user_count_update', {'grupo_id': grupo_id, 'count': current_count}, broadcast=True)
        
        emit('left_group', {
            'success': True, 
            'grupo_id': grupo_id,
            'message': '✅ Você saiu do grupo'
        })

@socketio.on('heartbeat')
def handle_heartbeat(data):
    session_token = data.get('session_token', '')
    device_id = data.get('device_id', '')
    
    if session_token and device_id:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('UPDATE sessoes SET last_seen = ? WHERE session_token = ? AND device_id = ?',
                      (datetime.now().isoformat(), session_token, device_id))
            conn.commit()
            conn.close()
        except:
            pass

@socketio.on('request_recovery')
def handle_recovery_request(data):
    ip = request.remote_addr
    
    if not check_rate_limit(ip):
        emit('recovery_result', {'success': False, 'msg': 'Aguarde 15 minutos'})
        return
    
    grupo_id = sanitize_input(data.get('grupo_id', ''), 10)
    usuario = sanitize_input(data.get('usuario', ''), 15)
    device_id = data.get('device_id', '').strip()
    
    if not grupo_id or not usuario or not device_id:
        emit('recovery_result', {'success': False, 'msg': 'Dados inválidos'})
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''SELECT g.grupo_uuid 
                 FROM grupos g
                 JOIN sessoes s ON g.grupo_uuid = s.grupo_uuid
                 WHERE g.grupo_id = ? AND s.usuario = ? AND s.device_id = ?''',
              (grupo_id, usuario, device_id))
    
    if not c.fetchone():
        emit('recovery_result', {'success': False, 'msg': 'Não encontrado'})
        conn.close()
        return
    
    conn.close()
    
    token = generate_token()
    expires = datetime.now() + timedelta(minutes=5)
    
    temp_tokens[token] = {
        'grupo_id': grupo_id,
        'usuario': usuario,
        'device_id': device_id,
        'expires': expires
    }
    
    emit('recovery_result', {
        'success': True,
        'msg': f'Token: {token}',
        'token': token
    })

@socketio.on('verify_recovery')
def handle_recovery_verify(data):
    token = data.get('token', '').strip()
    grupo_id = sanitize_input(data.get('grupo_id', ''), 10)
    usuario = sanitize_input(data.get('usuario', ''), 15)
    device_id = data.get('device_id', '').strip()
    
    token_info = temp_tokens.get(token)
    if not token_info:
        emit('recovery_verified', {'success': False, 'msg': 'Token inválido'})
        return
    
    if token_info['expires'] < datetime.now():
        del temp_tokens[token]
        emit('recovery_verified', {'success': False, 'msg': 'Token expirado'})
        return
    
    if (token_info['grupo_id'] != grupo_id or 
        token_info['usuario'] != usuario or 
        token_info['device_id'] != device_id):
        emit('recovery_verified', {'success': False, 'msg': 'Token não corresponde'})
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT grupo_uuid FROM grupos WHERE grupo_id = ?', (grupo_id,))
    result = c.fetchone()
    
    if not result:
        emit('recovery_verified', {'success': False, 'msg': 'Erro'})
        conn.close()
        return
    
    grupo_uuid = result[0]
    
    c.execute('DELETE FROM sessoes WHERE grupo_uuid = ? AND usuario = ? AND device_id = ?',
              (grupo_uuid, usuario, device_id))
    
    session_token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
    last_seen = datetime.now().isoformat()
    
    c.execute('''INSERT INTO sessoes (session_token, grupo_uuid, usuario, device_id, expires_at, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (session_token, grupo_uuid, usuario, device_id, expires_at, last_seen))
    
    conn.commit()
    conn.close()
    
    del temp_tokens[token]
    
    emit('recovery_verified', {
        'success': True,
        'msg': 'Acesso recuperado!',
        'session_token': session_token,
        'grupo_id': grupo_id,
        'usuario': usuario,
        'device_id': device_id
    })

if __name__ == '__main__':
    ip = get_local_ip()
    
    print("\n" + "="*50)
    print("💬 CHAT GRUPAL - TODOS OS BOTÕES FUNCIONANDO")
    print("="*50)
    print(f"🌐 URL: http://{ip}:8000")
    print("🔒 SEGURANÇA: Device ID ativo")
    print("🔄 Botões de voltar: ✅ FUNCIONANDO")
    print("="*50)
    
    socketio.run(app, host='0.0.0.0', port=8000, debug=False, allow_unsafe_werkzeug=True)
