"""
QuantumNet Flask Application

This is the main Flask application with all routes properly configured.
"""

import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
from datetime import datetime
import json

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from config import get_config
from src.server.database import DatabaseManager
try:
    from src.server.database_pg import PostgresDatabaseManager
except Exception:
    PostgresDatabaseManager = None
from src.ml.model_manager import ModelManager
from src.crypto.quantum_key_generator import QuantumKeyGenerator
from src.crypto.aes_encryption import AESEncryption

# Create Flask app
app = Flask(__name__)

# Load configuration
config_class = get_config()
app.config.from_object(config_class)

# Initialize SocketIO with Redis message queue for multi-instance sync
from config import get_redis_url
# Use Redis for cross-process pub/sub only if reachable; otherwise fall back to in-process
redis_url = get_redis_url()
message_queue_url = None
if redis_url:
    try:
        import redis as _redis
        _r = _redis.from_url(redis_url)
        _r.ping()
        message_queue_url = redis_url
    except Exception:
        message_queue_url = None

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    message_queue=message_queue_url,
    async_mode=app.config.get('SOCKETIO_ASYNC_MODE', 'eventlet')
)

# Global variables
active_sessions = {}
user_keys = {}
session_registry = {}  # { user_id: [session_id1, session_id2, ...] }

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize components
with app.app_context():
    # Initialize database: prefer PostgreSQL when DATABASE_URL is set
    database_url = os.environ.get('DATABASE_URL')
    if database_url and PostgresDatabaseManager is not None:
        app.db_manager = PostgresDatabaseManager(database_url)
        app.config['DB_BACKEND'] = 'postgres'
    else:
        app.db_manager = DatabaseManager(app.config['DATABASE_PATH'])
        app.config['DB_BACKEND'] = 'sqlite'
    
    # Initialize ML model manager
    app.model_manager = ModelManager(
        models_dir=os.path.dirname(app.config['ML_MODEL_PATH']),
        data_dir='data'
    )
    
    # Initialize quantum key generator
    app.quantum_generator = QuantumKeyGenerator()
    
    # Initialize AES encryption
    app.aes_encryption = AESEncryption()
    
    # Train ML model if not already trained
    if not app.model_manager.classifier.is_trained:
        print("Training ML model...")
        training_result = app.model_manager.train_model(
            samples_per_class=app.config['ML_TRAINING_SAMPLES_PER_CLASS']
        )
        if training_result['success']:
            print("ML model trained successfully!")
        else:
            print(f"ML model training failed: {training_result['error']}")


@app.route('/')
def index():
    """Home page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page: update bio/phone and show shared media."""
    user_id = session['user_id']
    if request.method == 'POST':
        bio = request.form.get('bio')
        phone = request.form.get('phone')
        app.db_manager.update_user_profile(user_id, bio, phone)
        flash('Profile updated', 'success')
        return redirect(url_for('profile'))
    user = app.db_manager.get_user_by_id(user_id)
    # Render profile page
    return render_template('profile.html', user=user)


@app.route('/api/profile/photo', methods=['POST'])
@login_required
def upload_profile_photo():
    """Upload and encrypt profile photo; store encrypted file and save path."""
    if 'photo' not in request.files:
        return jsonify({'success': False, 'error': 'No photo provided'})
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No photo selected'})
    try:
        img_bytes = file.read()
        # Compress/resize using Pillow
        from io import BytesIO
        from PIL import Image
        img = Image.open(BytesIO(img_bytes)).convert('RGB')
        img.thumbnail((1920, 1920))
        buf = BytesIO()
        img.save(buf, format='JPEG', quality=85)
        compressed = buf.getvalue()
        # Encrypt using quantum key if available
        user_id = session['user_id']
        key_bits = None
        if user_id in user_keys:
            key_id = user_keys[user_id]
            key_bits = app.quantum_generator.get_key(key_id)
        encrypted_content = compressed
        if key_bits:
            enc = app.aes_encryption.encrypt(compressed.decode('latin-1'), key_bits)
            if enc['success']:
                encrypted_content = enc['encrypted_data'].encode('latin-1')
        # Store to disk
        os.makedirs('static/uploads/profile', exist_ok=True)
        storage_name = f"user_{user_id}_profile.enc"
        storage_path = os.path.join('static/uploads/profile', storage_name)
        with open(storage_path, 'wb') as f:
            f.write(encrypted_content)
        app.db_manager.update_profile_photo_path(user_id, storage_path)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/u/<int:user_id>/photo')
@login_required
def serve_profile_photo(user_id):
    """Decrypt and serve a user's profile photo (if present)."""
    try:
        user = app.db_manager.get_user_by_id(user_id)
        path = user.get('profile_photo_path') if user else None
        if not path or not os.path.exists(path):
            # Return an inline SVG placeholder to avoid 404s when default image is missing
            placeholder_svg = (
                "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200' viewBox='0 0 200 200'>"
                "<rect width='200' height='200' fill='#e9ecef'/><circle cx='100' cy='80' r='40' fill='#adb5bd'/>"
                "<rect x='40' y='130' width='120' height='50' rx='25' fill='#adb5bd'/></svg>"
            )
            from flask import Response
            return Response(placeholder_svg, mimetype='image/svg+xml')
        with open(path, 'rb') as f:
            data = f.read()
        # Decrypt if possible using current viewer key; fallback raw
        viewer_id = session['user_id']
        if viewer_id in user_keys:
            key_id = user_keys[viewer_id]
            key_bits = app.quantum_generator.get_key(key_id)
            if key_bits:
                try:
                    dec = app.aes_encryption.decrypt(data.decode('latin-1'), key_bits)
                    if dec['success']:
                        data = dec['decrypted_message'].encode('latin-1')
                except Exception:
                    pass
        from flask import Response
        return Response(data, mimetype='image/jpeg')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if app.db_manager.get_user_by_username(username):
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if app.db_manager.get_user_by_email(email):
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        if app.config.get('DB_BACKEND') == 'postgres':
            import hashlib
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            user_id = app.db_manager.create_user(username, email, pwd_hash)
        else:
            user_id = app.db_manager.create_user(username, email, password)
        if user_id:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed', 'error')
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if app.config.get('DB_BACKEND') == 'postgres':
            import hashlib
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            user = app.db_manager.authenticate_user(username, pwd_hash)
        else:
            user = app.db_manager.authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """User logout."""
    # Clean up user session
    if 'user_id' in session:
        user_id = session['user_id']
        if user_id in active_sessions:
            del active_sessions[user_id]
        if user_id in user_keys:
            del user_keys[user_id]
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """User dashboard."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = app.db_manager.get_user_by_id(user_id)
    
    # Get user statistics
    stats = {
        'total_messages': app.db_manager.get_user_message_count(user_id),
        'active_sessions': len(active_sessions),
        'security_events': app.db_manager.get_user_security_events_count(user_id)
    }
    
    return render_template('dashboard.html', user=user, stats=stats)


@app.route('/chat')
def chat():
    """Secure chat interface."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = app.db_manager.get_user_by_id(user_id)
    
    # Get recent messages
    recent_messages = app.db_manager.get_recent_messages(limit=50)
    
    return render_template('chat.html', user=user, messages=recent_messages)


@app.route('/security')
def security():
    """This is Security monitoring page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = app.db_manager.get_user_by_id(user_id)
    
    # Get security events
    security_events = app.db_manager.get_user_security_events(user_id, limit=20)
    
    # Get security statistics
    security_stats = {
        'total_events': len(security_events),
        'threat_levels': {
            'LOW': sum(1 for event in security_events if event['threat_level'] == 'LOW'),
            'MEDIUM': sum(1 for event in security_events if event['threat_level'] == 'MEDIUM'),
            'HIGH': sum(1 for event in security_events if event['threat_level'] == 'HIGH'),
            'CRITICAL': sum(1 for event in security_events if event['threat_level'] == 'CRITICAL')
        }
    }
    
    return render_template('security.html', user=user, events=security_events, stats=security_stats)


@app.route('/api/security/metrics')
def security_metrics():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    try:
        key_stats = app.quantum_generator.get_key_statistics()
        db_stats = app.db_manager.get_database_stats() if hasattr(app.db_manager, 'get_database_stats') else {}
        # Approximate current QBER from last protocol record if present
        history = app.quantum_generator.get_protocol_history()
        qber = None
        if history:
            last = history[-1]
            qber = last.get('detection_probability', 0.0)
        return jsonify({
            'success': True,
            'key_stats': key_stats,
            'db_stats': db_stats,
            'qber': qber
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/bb84-demo')
def bb84_demo():
    """BB84 Quantum Key Distribution Demo page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = app.db_manager.get_user_by_id(user_id)
    
    return render_template('bb84_demo.html', user=user)


@app.route('/generate_key', methods=['POST'])
def generate_key():
    """Generate quantum key for user."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    session_id = request.json.get('session_id', f"session_{user_id}_{int(datetime.now().timestamp())}")
    
    try:
        # Generate quantum key
        result = app.quantum_generator.generate_single_key(
            user_id=str(user_id),
            session_id=session_id,
            num_bits=1000,
            enable_eavesdropping=False,
            expiry_hours=24
        )
        
        if result['success']:
            # Store key for user
            user_keys[user_id] = result['key_id']
            
            # Log security event
            app.db_manager.create_security_event(
                user_id=user_id,
                event_type='KEY_GENERATED',
                description=f'Quantum key generated (length: {result["key_length"]})',
                threat_level='LOW'
            )
            
            return jsonify({
                'success': True,
                'key_id': result['key_id'],
                'key_length': result['key_length'],
                'expiry_hours': result['expiry_hours']
            })
        else:
            return jsonify({'success': False, 'error': result['error']})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    """Encrypt a message using quantum key."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    message = request.json.get('message', '')
    
    if not message:
        return jsonify({'success': False, 'error': 'No message provided'})
    
    if user_id not in user_keys:
        return jsonify({'success': False, 'error': 'No quantum key available'})
    
    try:
        # Get quantum key
        key_id = user_keys[user_id]
        quantum_key = app.quantum_generator.get_key(key_id)
        
        if not quantum_key:
            return jsonify({'success': False, 'error': 'Quantum key expired or invalid'})
        
        # Encrypt message
        encryption_result = app.aes_encryption.encrypt(message, quantum_key)
        
        if encryption_result['success']:
            return jsonify({
                'success': True,
                'encrypted_data': encryption_result['encrypted_data'],
                'iv': encryption_result['iv']
            })
        else:
            return jsonify({'success': False, 'error': encryption_result['error']})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/online-users')
def get_online_users():
    """Get list of online users."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    try:
        online_users = app.db_manager.get_online_users()
        return jsonify({
            'success': True,
            'users': online_users
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
@app.route('/api/search/users')
def search_users():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'success': True, 'users': []})
    results = app.db_manager.search_users(q, limit=10)
    return jsonify({'success': True, 'users': results})


@app.route('/api/contacts', methods=['GET'])
def list_contacts():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    contacts = app.db_manager.list_contacts(session['user_id'])
    return jsonify({'success': True, 'contacts': contacts})


@app.route('/api/contacts/add', methods=['POST'])
def add_contact():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    contact_id = int(request.json.get('contact_id'))
    ok = app.db_manager.add_contact(session['user_id'], contact_id, 'normal')
    return jsonify({'success': ok})


@app.route('/api/contacts/remove', methods=['POST'])
def remove_contact():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    contact_id = int(request.json.get('contact_id'))
    ok = app.db_manager.remove_contact(session['user_id'], contact_id)
    return jsonify({'success': ok})


@app.route('/api/contacts/status', methods=['POST'])
def set_contact_status():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    contact_id = int(request.json.get('contact_id'))
    status = request.json.get('status', 'normal')
    ok = app.db_manager.set_contact_status(session['user_id'], contact_id, status)
    return jsonify({'success': ok})



@app.route('/api/user-sessions')
def get_user_sessions():
    """Get active sessions for current user."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    
    try:
        # Get sessions from registry
        user_sessions = session_registry.get(user_id, [])
        
        return jsonify({
            'success': True,
            'sessions': user_sessions,
            'session_count': len(user_sessions)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/messages')
def get_messages():
    """Get paginated messages for current user."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    recipient_id = request.args.get('recipient_id', 0, type=int)
    
    try:
        if recipient_id == 0:
            # Get general chat messages
            messages = app.db_manager.get_recent_messages(limit=limit)
        else:
            # Get messages between specific users
            messages = app.db_manager.get_messages_between_users(user_id, recipient_id, limit)
        
        return jsonify({
            'success': True,
            'messages': messages,
            'page': page,
            'limit': limit,
            'has_more': len(messages) == limit
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
@app.route('/api/messages/search')
def search_messages():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'success': True, 'messages': []})
    msgs = app.db_manager.search_messages(session['user_id'], q, limit=50)
    return jsonify({'success': True, 'messages': msgs})



@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload and encrypt a file."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    recipient_id = int(request.form.get('recipient_id', 0))
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    try:
        # Read file content
        file_content = file.read()
        file_size = len(file_content)
        
        # Check file size (max 100MB)
        if file_size > 100 * 1024 * 1024:
            return jsonify({'success': False, 'error': 'File too large (max 10MB)'})
        
        # Get quantum key for encryption
        key_bits = None
        if user_id in user_keys:
            key_id = user_keys[user_id]
            key_bits = app.quantum_generator.get_key(key_id)
        
        if not key_bits:
            # Generate new key if none exists
            result = app.quantum_generator.generate_single_key(
                user_id=str(user_id),
                session_id=f"file_{int(datetime.now().timestamp())}",
                num_bits=1000,
                enable_eavesdropping=False,
                expiry_hours=24
            )
            if result['success']:
                user_keys[user_id] = result['key_id']
                key_bits = app.quantum_generator.get_key(result['key_id'])
        
        # If image, compress and generate thumbnail
        thumbnail_path = None
        try:
            from PIL import Image
            from io import BytesIO
            if file.content_type.startswith('image/'):
                image = Image.open(BytesIO(file_content)).convert('RGB')
                image.thumbnail((1920, 1920))
                out = BytesIO()
                image.save(out, format='JPEG', quality=85)
                file_content = out.getvalue()
                # thumbnail 200x200
                thumb = image.copy()
                thumb.thumbnail((200, 200))
                os.makedirs('static/uploads/thumbs', exist_ok=True)
                thumb_name = f"thumb_{int(datetime.now().timestamp())}_{user_id}.jpg"
                thumbnail_path = os.path.join('static/uploads/thumbs', thumb_name)
                thumb.save(thumbnail_path, format='JPEG', quality=80)
        except Exception:
            pass

        # Encrypt file content
        encrypted_content = file_content
        encryption_used = False
        
        if key_bits:
            try:
                encryption_result = app.aes_encryption.encrypt(file_content.decode('latin-1'), key_bits)
                if encryption_result['success']:
                    encrypted_content = encryption_result['encrypted_data'].encode('latin-1')
                    encryption_used = True
            except:
                # If encryption fails, store unencrypted
                pass
        
        # Create file share record
        file_share_id = app.db_manager.create_file_share(
            sender_id=user_id,
            recipient_id=recipient_id,
            file_name=file.filename,
            file_type=file.content_type,
            file_size=file_size,
            encrypted_content=encrypted_content,
            encryption_used=encryption_used,
            thumbnail_path=thumbnail_path
        )
        
        if file_share_id:
            # Notify recipient via WebSocket
            socketio.emit('file_received', {
                'file_id': file_share_id,
                'file_name': file.filename,
                'file_size': file_size,
                'file_type': file.content_type,
                'sender_id': user_id,
                'encryption_used': encryption_used,
                'thumbnail_path': thumbnail_path,
                'timestamp': datetime.now().isoformat()
            }, room=f"user_{recipient_id}" if recipient_id > 0 else 'general')
            
            return jsonify({
                'success': True,
                'file_id': file_share_id,
                'file_name': file.filename,
                'file_size': file_size,
                'encryption_used': encryption_used,
                'thumbnail_path': thumbnail_path
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save file'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Download and decrypt a file."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    try:
        # Get file share record
        file_share = app.db_manager.get_file_share(file_id)
        if not file_share:
            flash('File not found', 'error')
            return redirect(url_for('chat'))
        
        # Check if user has access to this file
        if file_share['sender_id'] != user_id and file_share['recipient_id'] != user_id:
            flash('Access denied', 'error')
            return redirect(url_for('chat'))
        
        # Decrypt file content if encrypted
        file_content = file_share['encrypted_content']
        
        if file_share['encryption_used'] and user_id in user_keys:
            key_id = user_keys[user_id]
            key_bits = app.quantum_generator.get_key(key_id)
            
            if key_bits:
                try:
                    decryption_result = app.aes_encryption.decrypt(
                        file_content.decode('latin-1'), 
                        key_bits
                    )
                    if decryption_result['success']:
                        file_content = decryption_result['decrypted_message'].encode('latin-1')
                except:
                    # If decryption fails, return encrypted content
                    pass
        
        # Create response with file
        from flask import Response
        return Response(
            file_content,
            mimetype=file_share['file_type'],
            headers={
                'Content-Disposition': f'attachment; filename="{file_share["file_name"]}"'
            }
        )
    
    except Exception as e:
        flash(f'Download error: {str(e)}', 'error')
        return redirect(url_for('chat'))


@app.route('/upload-audio', methods=['POST'])
@login_required
def upload_audio():
    """Upload and encrypt an audio file."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    recipient_id = int(request.form.get('recipient_id', 0))
    
    if 'audio' not in request.files:
        return jsonify({'success': False, 'error': 'No audio file provided'})
    
    audio_file = request.files['audio']
    if audio_file.filename == '':
        return jsonify({'success': False, 'error': 'No audio file selected'})
    
    try:
        # Read audio content
        audio_content = audio_file.read()
        audio_size = len(audio_content)
        
        # Check file size (max 5MB for audio)
        if audio_size > 5 * 1024 * 1024:
            return jsonify({'success': False, 'error': 'Audio file too large (max 5MB)'})
        
        # Get quantum key for encryption
        key_bits = None
        if user_id in user_keys:
            key_id = user_keys[user_id]
            key_bits = app.quantum_generator.get_key(key_id)
        
        # Encrypt audio content
        encrypted_content = audio_content
        encryption_used = False
        
        if key_bits:
            try:
                encryption_result = app.aes_encryption.encrypt(audio_content.decode('latin-1'), key_bits)
                if encryption_result['success']:
                    encrypted_content = encryption_result['encrypted_data'].encode('latin-1')
                    encryption_used = True
            except:
                pass
        
        # Create file share record for audio
        audio_share_id = app.db_manager.create_file_share(
            sender_id=user_id,
            recipient_id=recipient_id,
            file_name=f"voice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav",
            file_type='audio/wav',
            file_size=audio_size,
            encrypted_content=encrypted_content,
            encryption_used=encryption_used
        )
        
        if audio_share_id:
            # Notify recipient via WebSocket
            socketio.emit('voice_message_received', {
                'voice_id': audio_share_id,
                'sender_id': user_id,
                'file_size': audio_size,
                'encryption_used': encryption_used,
                'timestamp': datetime.now().isoformat()
            }, room=f"user_{recipient_id}" if recipient_id > 0 else 'general')
            
            return jsonify({
                'success': True,
                'voice_id': audio_share_id,
                'file_size': audio_size,
                'encryption_used': encryption_used
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save audio'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# SocketIO Events
@socketio.on('connect')
def handle_connect(auth=None):
    """Handle client connection."""
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        
        # Register session for cross-device sync
        if user_id not in session_registry:
            session_registry[user_id] = []
        session_registry[user_id].append(request.sid)
        
        # Add user to active sessions
        active_sessions[user_id] = {
            'username': username,
            'connected_at': datetime.now().isoformat(),
            'socket_id': request.sid
        }
        
        # Update user presence in database
        app.db_manager.update_user_presence(user_id, True)
        
        # Create/update device record
        device_info = request.headers.get('User-Agent', 'Unknown')
        app.db_manager.create_device(
            user_id=user_id,
            device_id=request.sid,
            device_name=f"Web Browser - {device_info[:50]}",
            browser=request.headers.get('User-Agent', 'Unknown'),
            ip_address=request.remote_addr
        )
        
        # Join user to their personal room
        join_room(f"user_{user_id}")
        
        # Notify other users about presence change
        emit('user_status_changed', {
            'user_id': user_id,
            'username': username,
            'status': 'online',
            'last_seen': datetime.now().isoformat()
        }, room='general', include_self=False)
        
        print(f"User {username} came online (sessions: {len(session_registry[user_id])})")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        
        # Remove session from registry
        if user_id in session_registry and request.sid in session_registry[user_id]:
            session_registry[user_id].remove(request.sid)
        
        # If no more sessions for this user, mark as offline
        if user_id not in session_registry or len(session_registry[user_id]) == 0:
            # Update user presence in database
            app.db_manager.update_user_presence(user_id, False)
            
            # Remove from active sessions
            if user_id in active_sessions:
                del active_sessions[user_id]
            
            # Notify other users about presence change
            emit('user_status_changed', {
                'user_id': user_id,
                'username': username,
                'status': 'offline',
                'last_seen': datetime.now().isoformat()
            }, room='general', include_self=False)
            
            print(f"User {username} went offline")
        else:
            print(f"User {username} disconnected from one device (sessions remaining: {len(session_registry[user_id])})")
        
        # Leave user room
        leave_room(f"user_{user_id}")


@socketio.on('join_chat')
def handle_join_chat():
    """Handle user joining chat."""
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        
        # Join general chat room
        join_room('general')
        
        emit('chat_joined', {
            'message': f'{username} joined the chat',
            'timestamp': datetime.now().isoformat()
        }, room='general')


@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending encrypted message."""
    if 'user_id' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    sender_id = session['user_id']
    username = session['username']
    message_text = data.get('message', '')
    recipient_id = data.get('recipient_id', None)  # For direct messages
    reply_to = data.get('reply_to')
    
    if not message_text:
        emit('error', {'message': 'No message provided'})
        return
    
    try:
        # Encrypt message if quantum key is available
        encrypted_message = message_text
        encryption_used = False
        
        if sender_id in user_keys:
            key_id = user_keys[sender_id]
            quantum_key = app.quantum_generator.get_key(key_id)
            
            if quantum_key:
                encryption_result = app.aes_encryption.encrypt(message_text, quantum_key)
                if encryption_result['success']:
                    encrypted_message = encryption_result['encrypted_data']
                    encryption_used = True
        
        # For now, we'll use a general chat (recipient_id = 0 for broadcast)
        if not recipient_id:
            recipient_id = 0  # General chat
        
        # Save message to database
        message_id = app.db_manager.create_message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            content=message_text,
            encrypted_content=encrypted_message,
            encryption_used=encryption_used,
            reply_to=reply_to
        )
        
        # Prepare message data
        message_data = {
            'id': message_id,
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            'username': username,
            'content': message_text,
            'encrypted_content': encrypted_message,
            'encryption_used': encryption_used,
            'reply_to': reply_to,
            'status': 'pending',
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to recipient(s) - for general chat, broadcast to all
        if recipient_id == 0:
            emit('message_received', message_data, room='general')
        else:
            # Send to specific recipient - broadcast to ALL their active sessions
            if recipient_id in session_registry:
                for session_id in session_registry[recipient_id]:
                    emit('message_received', message_data, room=session_id)
            else:
                # Fallback to user room if session registry not available
                emit('message_received', message_data, room=f"user_{recipient_id}")
        
        # Mark as delivered immediately (since we're using WebSocket)
        app.db_manager.update_message_status(message_id, 'delivered')
        
        # Notify sender about delivery - broadcast to ALL their sessions
        if sender_id in session_registry:
            for session_id in session_registry[sender_id]:
                emit('message_delivered', {
                    'message_id': message_id,
                    'status': 'delivered',
                    'delivered_at': datetime.now().isoformat()
                }, room=session_id)
        else:
            emit('message_delivered', {
                'message_id': message_id,
                'status': 'delivered',
                'delivered_at': datetime.now().isoformat()
            }, room=f"user_{sender_id}")
        
        # Log security event
        app.db_manager.create_security_event(
            user_id=sender_id,
            event_type='MESSAGE_SENT',
            description=f'Message sent (encrypted: {encryption_used})',
            threat_level='LOW'
        )
        
    except Exception as e:
        emit('error', {'message': f'Failed to send message: {str(e)}'})


@socketio.on('react_to_message')
def handle_react_to_message(data):
    if 'user_id' not in session:
        return
    message_id = data.get('message_id')
    emoji = data.get('emoji', '👍')
    if not message_id:
        return
    if app.db_manager.react_to_message(message_id, emoji):
        emit('message_reacted', {'message_id': message_id, 'emoji': emoji}, room='general')


@socketio.on('delete_message_for_me')
def handle_delete_for_me(data):
    if 'user_id' not in session:
        return
    message_id = data.get('message_id')
    if message_id and app.db_manager.mark_message_deleted(message_id, session['user_id']):
        emit('message_deleted', {'message_id': message_id, 'scope': 'me'}, room=request.sid)


@socketio.on('delete_message_for_everyone')
def handle_delete_for_everyone(data):
    if 'user_id' not in session:
        return
    message_id = data.get('message_id')
    if message_id and app.db_manager.delete_message_for_everyone(message_id):
        emit('message_deleted', {'message_id': message_id, 'scope': 'all'}, room='general')


@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    """Handle marking message as read."""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    message_id = data.get('message_id')
    
    if not message_id:
        return
    
    try:
        # Update message status to read
        success = app.db_manager.update_message_status(message_id, 'read')
        
        if success:
            # Get the sender of the message to notify them
            # For now, we'll broadcast to all users (in a real app, you'd query the message sender)
            # Notify all users that message was read
            emit('message_read', {
                'message_id': message_id,
                'status': 'read',
                'read_at': datetime.now().isoformat()
            }, room='general')
            
            print(f"Message {message_id} marked as read by user {user_id}")
        
    except Exception as e:
        print(f"Error marking message as read: {e}")


@socketio.on('message_delivered')
def handle_message_delivered(data):
    """Handle message delivery confirmation."""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    message_id = data.get('message_id')
    
    if not message_id:
        return
    
    try:
        # Update message status to delivered
        success = app.db_manager.update_message_status(message_id, 'delivered')
        
        if success:
            print(f"Message {message_id} delivered to user {user_id}")
        
    except Exception as e:
        print(f"Error updating message delivery: {e}")


@socketio.on('typing_start')
def handle_typing_start(data):
    """Handle user starting to type."""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    username = session['username']
    recipient_id = data.get('recipient_id', 0)  # 0 for general chat
    
    # Notify recipient(s) that user is typing
    if recipient_id == 0:
        emit('user_typing', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, room='general', include_self=False)
    else:
        emit('user_typing', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, room=f"user_{recipient_id}")


@socketio.on('typing_stop')
def handle_typing_stop(data):
    """Handle user stopping typing."""
    if 'user_id' not in session:
        return
    
    user_id = session['user_id']
    username = session['username']
    recipient_id = data.get('recipient_id', 0)  # 0 for general chat
    
    # Notify recipient(s) that user stopped typing
    if recipient_id == 0:
        emit('user_stopped_typing', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, room='general', include_self=False)
    else:
        emit('user_stopped_typing', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, room=f"user_{recipient_id}")


if __name__ == '__main__':
    # Get host and port from configuration
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    print(f"Starting QuantumNet server on {host}:{port}")
    print(f"Configuration: development")
    print(f"Debug mode: {app.config['DEBUG']}")
    
    socketio.run(
        app,
        host=host,
        port=port,
        debug=app.config['DEBUG'],
        allow_unsafe_werkzeug=True
    )
