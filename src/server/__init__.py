"""
QuantumNet Flask Web Application

This module implements the main Flask web application with authentication,
secure chat, and security monitoring functionality.
"""

import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.crypto.quantum_key_generator import QuantumKeyGenerator
from src.crypto.aes_encryption import AESEncryption
from src.ml.model_manager import ModelManager
from src.server.database import DatabaseManager
from src.server.models import User, Message, SecurityEvent
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables for active sessions
active_sessions = {}
user_keys = {}


@app.route('/')
def index():
    """Home page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


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
    user = db_manager.get_user_by_id(user_id)
    
    # Get user statistics
    stats = {
        'total_messages': db_manager.get_user_message_count(user_id),
        'active_sessions': len(active_sessions),
        'security_events': db_manager.get_user_security_events_count(user_id)
    }
    
    return render_template('dashboard.html', user=user, stats=stats)


@app.route('/chat')
def chat():
    """Secure chat interface."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = db_manager.get_user_by_id(user_id)
    
    # Get recent messages
    recent_messages = db_manager.get_recent_messages(limit=50)
    
    return render_template('chat.html', user=user, messages=recent_messages)


@app.route('/security')
def security():
    """Security monitoring page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = db_manager.get_user_by_id(user_id)
    
    # Get security events
    security_events = db_manager.get_user_security_events(user_id, limit=20)
    
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


@app.route('/generate_key', methods=['POST'])
def generate_key():
    """Generate quantum key for user."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    session_id = request.json.get('session_id', f"session_{user_id}_{int(datetime.now().timestamp())}")
    
    try:
        # Generate quantum key
        result = quantum_key_generator.generate_single_key(
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
            db_manager.create_security_event(
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
        quantum_key = quantum_key_generator.get_key(key_id)
        
        if not quantum_key:
            return jsonify({'success': False, 'error': 'Quantum key expired or invalid'})
        
        # Encrypt message
        encryption_result = aes_encryption.encrypt(message, quantum_key)
        
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


@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    """Decrypt a message using quantum key."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_id = session['user_id']
    encrypted_data = request.json.get('encrypted_data', '')
    iv = request.json.get('iv', '')
    
    if not encrypted_data or not iv:
        return jsonify({'success': False, 'error': 'Missing encryption data'})
    
    if user_id not in user_keys:
        return jsonify({'success': False, 'error': 'No quantum key available'})
    
    try:
        # Get quantum key
        key_id = user_keys[user_id]
        quantum_key = quantum_key_generator.get_key(key_id)
        
        if not quantum_key:
            return jsonify({'success': False, 'error': 'Quantum key expired or invalid'})
        
        # Decrypt message
        decryption_result = aes_encryption.decrypt(encrypted_data, iv, quantum_key)
        
        if decryption_result['success']:
            return jsonify({
                'success': True,
                'decrypted_message': decryption_result['decrypted_data']
            })
        else:
            return jsonify({'success': False, 'error': decryption_result['error']})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# SocketIO Events
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        
        # Add user to active sessions
        active_sessions[user_id] = {
            'username': username,
            'connected_at': datetime.now().isoformat(),
            'socket_id': request.sid
        }
        
        # Join user to their personal room
        join_room(f"user_{user_id}")
        
        # Notify other users
        emit('user_connected', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, room='general', include_self=False)
        
        print(f"User {username} connected")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        
        # Remove from active sessions
        if user_id in active_sessions:
            del active_sessions[user_id]
        
        # Leave user room
        leave_room(f"user_{user_id}")
        
        # Notify other users
        emit('user_disconnected', {
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }, room='general', include_self=False)
        
        print(f"User {username} disconnected")


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
    
    user_id = session['user_id']
    username = session['username']
    message_text = data.get('message', '')
    
    if not message_text:
        emit('error', {'message': 'No message provided'})
        return
    
    try:
        # Encrypt message if quantum key is available
        encrypted_message = message_text
        encryption_used = False
        
        if user_id in user_keys:
            key_id = user_keys[user_id]
            quantum_key = quantum_key_generator.get_key(key_id)
            
            if quantum_key:
                encryption_result = aes_encryption.encrypt(message_text, quantum_key)
                if encryption_result['success']:
                    encrypted_message = encryption_result['encrypted_data']
                    encryption_used = True
        
        # Save message to database
        message_id = db_manager.create_message(
            user_id=user_id,
            content=message_text,
            encrypted_content=encrypted_message,
            encryption_used=encryption_used
        )
        
        # Broadcast message
        message_data = {
            'id': message_id,
            'user_id': user_id,
            'username': username,
            'content': message_text,
            'encrypted_content': encrypted_message,
            'encryption_used': encryption_used,
            'timestamp': datetime.now().isoformat()
        }
        
        emit('message_received', message_data, room='general')
        
        # Log security event
        db_manager.create_security_event(
            user_id=user_id,
            event_type='MESSAGE_SENT',
            description=f'Message sent (encrypted: {encryption_used})',
            threat_level='LOW'
        )
        
    except Exception as e:
        emit('error', {'message': f'Failed to send message: {str(e)}'})


@socketio.on('security_monitor')
def handle_security_monitor():
    """Handle security monitoring request."""
    if 'user_id' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    user_id = session['user_id']
    
    try:
        # Get recent security events
        security_events = db_manager.get_user_security_events(user_id, limit=10)
        
        # Analyze events with ML model
        if model_manager.classifier.is_trained:
            for event in security_events:
                # Create features for ML analysis
                features = {
                    'key_length': event.get('key_length', 0),
                    'detection_probability': event.get('detection_probability', 0),
                    'hamming_distance': event.get('hamming_distance', 0),
                    'key_entropy': event.get('key_entropy', 0),
                    'transmission_success_rate': event.get('transmission_success_rate', 1),
                    'noise_level': event.get('noise_level', 0),
                    'protocol_success': event.get('protocol_success', 1),
                    'eavesdropping_detected': event.get('eavesdropping_detected', 0),
                    'error_rate': event.get('error_rate', 0),
                    'timing_anomaly': event.get('timing_anomaly', 0),
                    'key_reuse_count': event.get('key_reuse_count', 0),
                    'session_duration': event.get('session_duration', 0)
                }
                
                # Get ML prediction
                prediction = model_manager.predict_security_threat(features)
                
                if prediction['success']:
                    # Update event with ML analysis
                    db_manager.update_security_event(
                        event['id'],
                        ml_prediction=prediction['prediction_label'],
                        threat_level=prediction['threat_level'],
                        confidence=prediction['confidence']
                    )
        
        emit('security_update', {
            'events': security_events,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        emit('error', {'message': f'Security monitoring failed: {str(e)}'})


if __name__ == '__main__':
    # Initialize database
    db_manager.init_database()
    
    # Train ML model if not already trained
    if not model_manager.classifier.is_trained:
        print("Training ML model...")
        training_result = model_manager.train_model(samples_per_class=500)
        if training_result['success']:
            print("ML model trained successfully!")
        else:
            print(f"ML model training failed: {training_result['error']}")
    
    # Run the application
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
