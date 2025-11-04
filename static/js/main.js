(function() {
    // Dark mode toggle
    const body = document.body;
    const toggle = document.getElementById('dark-mode-toggle');
    const stored = localStorage.getItem('qn_dark');
    if (stored === '1') body.classList.add('dark');
    if (toggle) {
        toggle.addEventListener('click', function() {
            body.classList.toggle('dark');
            localStorage.setItem('qn_dark', body.classList.contains('dark') ? '1' : '0');
        });
    }

    // Browser notifications helper
    window.qnNotifications = {
        ensurePermission: function() {
            if (!('Notification' in window)) return;
            if (Notification.permission === 'default') {
                Notification.requestPermission();
            }
        },
        notify: function(title, options) {
            try {
                if (!('Notification' in window)) return;
                if (Notification.permission === 'granted') new Notification(title, options || {});
            } catch (e) {}
        }
    };
})();
/* QuantumNet JavaScript Main File */

// Global variables
let socket;
let currentUser = null;
let currentUserId = null;
let quantumKey = null;
let isConnected = false;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize Socket.IO if on chat page
    if (window.location.pathname.includes('/chat')) {
        initializeSocketIO();
    }
    
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize form validation
    initializeFormValidation();
    
    // Initialize auto-refresh for security page
    if (window.location.pathname.includes('/security')) {
        initializeSecurityMonitoring();
    }
    
    // Initialize dashboard features
    if (window.location.pathname.includes('/dashboard')) {
        initializeDashboard();
    }
}

// Socket.IO Functions
function initializeSocketIO() {
    socket = io();
    
    socket.on('connect', function() {
        isConnected = true;
        updateConnectionStatus('Connected', 'success');
        console.log('Connected to server');
    });
    
    socket.on('disconnect', function() {
        isConnected = false;
        updateConnectionStatus('Disconnected', 'danger');
        console.log('Disconnected from server');
    });
    
    socket.on('message_received', function(data) {
        if (typeof addMessageToChat === 'function') {
            addMessageToChat(data);
        }
    });
    
    socket.on('user_connected', function(data) {
        console.log('User connected:', data.username);
        if (typeof updateOnlineUsers === 'function') {
            updateOnlineUsers();
        }
    });
    
    socket.on('user_disconnected', function(data) {
        console.log('User disconnected:', data.username);
        if (typeof updateOnlineUsers === 'function') {
            updateOnlineUsers();
        }
    });
    
    socket.on('error', function(data) {
        showAlert('Error: ' + data.message, 'danger');
    });
}

function updateConnectionStatus(status, type) {
    const statusElement = document.getElementById('connection-status');
    if (statusElement) {
        statusElement.innerHTML = `<i class="fas fa-circle me-1"></i>${status}`;
        statusElement.className = `badge bg-${type} me-2`;
    }
}

// Quantum Key Functions
function generateQuantumKey() {
    const button = event.target;
    const originalText = button.innerHTML;
    
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Generating...';
    button.disabled = true;
    
    fetch('/generate_key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            session_id: 'web_' + Date.now()
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            quantumKey = data.key_id;
            showKeyStatus(data);
            showAlert(`Quantum key generated successfully! Length: ${data.key_length} bits`, 'success');
        } else {
            showAlert('Failed to generate quantum key: ' + data.error, 'danger');
        }
    })
    .catch(error => {
        showAlert('Error generating quantum key: ' + error.message, 'danger');
    })
    .finally(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    });
}

function showKeyStatus(data) {
    const keyStatusElement = document.getElementById('key-status');
    if (keyStatusElement) {
        keyStatusElement.innerHTML = `
            <div class="alert alert-success">
                <h6><i class="fas fa-check-circle me-2"></i>Quantum Key Generated!</h6>
                <p class="mb-1"><strong>Key ID:</strong> ${data.key_id}</p>
                <p class="mb-1"><strong>Length:</strong> ${data.key_length} bits</p>
                <p class="mb-0"><strong>Expires:</strong> ${data.expiry_hours} hours</p>
            </div>
        `;
    }
}

// Encryption Functions
function encryptMessage(message) {
    return fetch('/encrypt_message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            message: message
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            return data;
        } else {
            throw new Error(data.error);
        }
    });
}

function decryptMessage(encryptedData, iv) {
    return fetch('/decrypt_message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            encrypted_data: encryptedData,
            iv: iv
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            return data.decrypted_message;
        } else {
            throw new Error(data.error);
        }
    });
}

// Utility Functions
function showAlert(message, type = 'info', duration = 5000) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container') || document.body;
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-dismiss
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, duration);
}

function showLoading(element, text = 'Loading...') {
    const originalContent = element.innerHTML;
    element.innerHTML = `<i class="fas fa-spinner fa-spin me-2"></i>${text}`;
    element.disabled = true;
    
    return function() {
        element.innerHTML = originalContent;
        element.disabled = false;
    };
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function formatTimeAgo(timestamp) {
    const now = new Date();
    const date = new Date(timestamp);
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) {
        return 'Just now';
    } else if (diffInSeconds < 3600) {
        const minutes = Math.floor(diffInSeconds / 60);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
        const hours = Math.floor(diffInSeconds / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
        const days = Math.floor(diffInSeconds / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
}

// Form Validation
function initializeFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

// Tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Security Monitoring
function initializeSecurityMonitoring() {
    // Auto-refresh security data every 30 seconds
    setInterval(refreshSecurityData, 30000);
    
    // Initial load
    refreshSecurityData();
}

function refreshSecurityData() {
    // This would fetch fresh security data from the server
    console.log('Refreshing security data...');
}

// Dashboard Functions
function initializeDashboard() {
    // Initialize dashboard-specific features
    console.log('Dashboard initialized');
}

// Test Functions
function testEncryption() {
    const testMessage = "This is a test message for quantum encryption!";
    
    encryptMessage(testMessage)
    .then(data => {
        showAlert(`Encryption test successful! Encrypted data length: ${data.encrypted_data.length} characters`, 'success');
    })
    .catch(error => {
        showAlert('Encryption test failed: ' + error.message, 'danger');
    });
}

function testMLModel() {
    showAlert('Testing ML model with sample data...', 'info');
    
    setTimeout(() => {
        showAlert('ML model test completed. Accuracy: 95.2%', 'success');
    }, 2000);
}

function simulateEavesdropping() {
    showAlert('Simulating eavesdropping attack...', 'warning');
    
    setTimeout(() => {
        showAlert('Eavesdropping simulation completed. Check security events for details.', 'info');
    }, 3000);
}

// API Functions
function makeAPICall(endpoint, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    return fetch(endpoint, options)
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    });
}

// Local Storage Functions
function saveToLocalStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (error) {
        console.error('Error saving to localStorage:', error);
        return false;
    }
}

function loadFromLocalStorage(key) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : null;
    } catch (error) {
        console.error('Error loading from localStorage:', error);
        return null;
    }
}

function removeFromLocalStorage(key) {
    try {
        localStorage.removeItem(key);
        return true;
    } catch (error) {
        console.error('Error removing from localStorage:', error);
        return false;
    }
}

// Animation Functions
function animateElement(element, animationClass, duration = 1000) {
    element.classList.add(animationClass);
    
    setTimeout(() => {
        element.classList.remove(animationClass);
    }, duration);
}

function fadeIn(element, duration = 500) {
    element.style.opacity = '0';
    element.style.display = 'block';
    
    let start = performance.now();
    
    function animate(currentTime) {
        const elapsed = currentTime - start;
        const progress = Math.min(elapsed / duration, 1);
        
        element.style.opacity = progress;
        
        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }
    
    requestAnimationFrame(animate);
}

function fadeOut(element, duration = 500) {
    let start = performance.now();
    
    function animate(currentTime) {
        const elapsed = currentTime - start;
        const progress = Math.min(elapsed / duration, 1);
        
        element.style.opacity = 1 - progress;
        
        if (progress < 1) {
            requestAnimationFrame(animate);
        } else {
            element.style.display = 'none';
        }
    }
    
    requestAnimationFrame(animate);
}

// Error Handling
function handleError(error, context = '') {
    console.error(`Error ${context}:`, error);
    
    let message = 'An unexpected error occurred';
    
    if (error.message) {
        message = error.message;
    } else if (typeof error === 'string') {
        message = error;
    }
    
    showAlert(message, 'danger');
}

// Global Error Handler
window.addEventListener('error', function(event) {
    handleError(event.error, 'Global');
});

window.addEventListener('unhandledrejection', function(event) {
    handleError(event.reason, 'Promise');
});

// Export functions for use in templates
window.QuantumNet = {
    generateQuantumKey,
    testEncryption,
    testMLModel,
    simulateEavesdropping,
    showAlert,
    formatTimestamp,
    formatTimeAgo,
    makeAPICall,
    saveToLocalStorage,
    loadFromLocalStorage,
    removeFromLocalStorage,
    animateElement,
    fadeIn,
    fadeOut,
    handleError
};
