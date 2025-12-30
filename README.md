# QuantumNet - Hybrid Quantum-Secure Messaging

QuantumNet is a production-ready messaging application that demonstrates **Post-Quantum Cryptography (PQC)** and **Quantum Key Distribution (QKD)** simulation. It is designed to protect against "Harvest Now, Decrypt Later" attacks by combining the laws of physics with advanced lattice-based mathematics.

## 🚀 Features

### Core Security
- **Hybrid Cryptography**: Combines **BB84 (Quantum Layer)**, **CRYSTALS-Kyber-768 (Math Layer)**, and **AES-256-GCM (Encryption Layer)**.
- **Quantum Key Distribution (QKD)**: Simulates the exchange of photons to generate unhackable keys.
- **Eavesdropping Detection**: Real-time monitoring of **Quantum Bit Error Rate (QBER)** to detect interception attempts.
- **Forward Secrecy**: Keys are rotated frequently, ensuring past messages remain secure even if a key is compromised.

### User Experience
- **Real-Time Messaging**: Instant, encrypted chat powered by **Socket.IO**.
- **Contact System**: Search for users, add friends, and manage your contact list.
- **File Sharing**: Securely upload and share encrypted files.
- **Live Demo**: A visual walkthrough of the quantum encryption process (accessible without login).

### Monitoring & Insights
- **Security Dashboard**: View real-time metrics like active keys, QBER, and threat logs.
- **Informational Pages**: 
    - **About**: Deep dive into the technology with interactive charts and comparisons.
    - **Contact**: Meet the squad and get in touch.

## 🛠️ Tech Stack

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **Database**: SQLAlchemy (Async) with SQLite (Dev) / PostgreSQL (Prod)
- **Real-time**: Python-SocketIO
- **Cryptography**: 
    - `pycryptodome` (AES-GCM)
    - `kyber-py` (PQC)
    - Custom BB84 Simulation Logic

### Frontend
- **Framework**: React 18 with Vite
- **Styling**: TailwindCSS
- **Animations**: Framer Motion
- **Charts**: Chart.js
- **Icons**: Lucide React

## 📦 Installation

### Prerequisites
- Python 3.11+
- Node.js 18+

### Backend Setup
1. Navigate to the `backend` directory:
   ```bash
   cd backend
   ```
2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the server:
   ```bash
   uvicorn app.main:app --reload
   ```
   The API will be available at `http://127.0.0.1:8000`.

### Frontend Setup
1. Navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```
   The application will start at `http://localhost:5173`.

## 🧪 Usage Guide

1. **Register & Login**: Create an account to generate your unique Quantum Identity.
2. **Add Contacts**: Use the sidebar to search for other users (e.g., "Alice", "Bob") and add them.
3. **Start Chatting**: Select a contact to begin a secure conversation. The **Quantum Handshake** happens automatically in the background.
4. **Check Security**: Click the "Activity" icon in the sidebar to view the **Security Dashboard**.
5. **Try the Demo**: Log out and click "Live Demo" on the landing page to see the encryption visualization.

## ⚠️ Security Note
This application **simulates** the Quantum Key Distribution (BB84) layer as it requires physical quantum hardware (single-photon emitters/detectors). The Kyber implementation and AES-256 encryption are functionally correct and follow standard cryptographic principles.
