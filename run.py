"""
QuantumNet Main Application Entry Point

This is the main entry point for the QuantumNet application.
"""

import os
import sys

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

if __name__ == '__main__':
    # Import and run the Flask app
    from app import app, socketio
    
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
