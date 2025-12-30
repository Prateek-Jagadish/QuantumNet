# QuantumNet Backend API

The backend for QuantumNet is a high-performance, asynchronous API built with **FastAPI**. It handles user authentication, real-time WebSocket communication, and the complex cryptographic operations required for the hybrid security architecture.

## 🏗️ Architecture

The backend is organized into a modular structure:

- **`app/api/`**: REST API endpoints.
    - `auth.py`: JWT authentication, registration, and login.
    - `chat.py`: Message history and file uploads.
    - `contacts.py`: Contact management (search, add, list).
    - `dashboard.py`: Security metrics and event logging.
    - `messages.py`: Offline message retrieval.
- **`app/websocket/`**: Real-time communication logic.
    - `server.py`: Socket.IO event handlers (`send_message`, `receive_message`, `authenticate`).
- **`app/services/`**: Core business logic.
    - `chat_service.py`: Handles AES-256 encryption/decryption of messages.
    - `quantum_service.py`: Simulates BB84 and implements Kyber key encapsulation.
- **`app/models/`**: SQLAlchemy database models.
    - `User`: Stores user credentials (hashed) and profile info.
    - `Message`: Stores encrypted message content.
    - `Contact`: Manages user relationships.
    - `HybridSessionKey`: Stores the derived keys for E2EE.
    - `SecurityEvent`: Logs threats and system events.

## 🔐 Cryptography Implementation

### 1. Quantum Layer (BB84 Simulation)
- **Location**: `app/crypto/bb84.py`
- **Function**: Simulates the exchange of qubits (photons) to generate a shared secret.
- **Security Check**: Calculates **QBER (Quantum Bit Error Rate)**. If QBER > 11%, the key exchange is aborted (simulating an eavesdropper).

### 2. Math Layer (Post-Quantum Cryptography)
- **Location**: `app/crypto/kyber.py`
- **Algorithm**: **CRYSTALS-Kyber-768** (NIST ML-KEM Standard).
- **Function**: Uses Module-Lattice problems to securely encapsulate a shared secret.
- **Role**: Provides security against future quantum computers.

### 3. Encryption Layer (Symmetric)
- **Location**: `app/services/chat_service.py`
- **Algorithm**: **AES-256-GCM**.
- **Function**: Encrypts the actual message payload using a **Hybrid Key**.
- **Hybrid Key Derivation**: The final session key is derived by combining the BB84 secret and the Kyber secret using **HKDF-SHA256**.

## 🚀 API Endpoints

### Authentication
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | Register a new user (generates Kyber keys). |
| `POST` | `/api/v1/auth/token` | Login and receive a JWT access token. |
| `GET` | `/api/v1/auth/me` | Get current user profile. |

### Contacts
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/contacts/` | Get all contacts for the current user. |
| `POST` | `/api/v1/contacts/` | Add a new contact by username. |
| `GET` | `/api/v1/contacts/search` | Search for users by username. |

### Chat & Messages
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/messages/history/{contact_id}` | Get chat history with a specific contact. |
| `GET` | `/api/v1/messages/offline` | Fetch undelivered messages. |
| `POST` | `/api/v1/chat/upload` | Upload and encrypt a file. |

### Security Dashboard
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/dashboard/metrics` | Get real-time security metrics (QBER, Active Keys). |
| `GET` | `/api/v1/dashboard/keys` | List active hybrid session keys. |
| `GET` | `/api/v1/dashboard/events` | Get security event logs. |

## 🔌 WebSocket Events

The application uses **Socket.IO** for real-time events.

- **`authenticate`**: Client sends JWT token to join their personal room.
- **`send_message`**: Client sends an encrypted message payload.
- **`receive_message`**: Server pushes a new message to the recipient.
- **`message_status`**: Server updates message status (sent/delivered/read).

## 🗄️ Database

The project uses **SQLite** for development simplicity but is production-ready for **PostgreSQL**.
- **Configuration**: `app/core/config.py`
- **Migration**: Tables are automatically created via `app/database.py` on startup.
