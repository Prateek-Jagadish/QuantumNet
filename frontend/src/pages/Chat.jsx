import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { io } from 'socket.io-client';
import { Send, Paperclip, Image as ImageIcon, MoreVertical, ShieldCheck, Copy, Activity, User, LogOut, Search, UserPlus, MessageSquare } from 'lucide-react';
import api from '../services/api';
import { motion, AnimatePresence } from 'framer-motion';

const Chat = () => {
    const { user, logout } = useAuth();
    const [socket, setSocket] = useState(null);
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [recipient, setRecipient] = useState(null); // Full user object
    const [contacts, setContacts] = useState([]);
    const [searchResults, setSearchResults] = useState([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [activeTab, setActiveTab] = useState('contacts'); // 'contacts' or 'search'
    const messagesEndRef = useRef(null);
    const fileInputRef = useRef(null);

    // Socket Connection
    useEffect(() => {
        const newSocket = io();
        setSocket(newSocket);

        newSocket.on('connect', () => {
            console.log('Connected to socket');
            newSocket.emit('authenticate', { token: localStorage.getItem('token') });
        });

        newSocket.on('receive_message', (message) => {
            setMessages((prev) => [...prev, message]);
            if (message.sender_id === recipient?.id) {
                newSocket.emit('mark_read', { message_id: message.id, sender_id: message.sender_id });
            }
        });

        newSocket.on('message_sent', (message) => {
            setMessages((prev) => [...prev, message]);
        });

        newSocket.on('message_read', (data) => {
            setMessages((prev) => prev.map(msg =>
                msg.id === data.message_id ? { ...msg, read_at: data.read_at, status: 'read' } : msg
            ));
        });

        return () => newSocket.close();
    }, [recipient]);

    // Fetch Contacts
    useEffect(() => {
        fetchContacts();
    }, []);

    const fetchContacts = async () => {
        try {
            const res = await api.get('/contacts/');
            setContacts(res.data);
        } catch (err) {
            console.error("Failed to fetch contacts", err);
        }
    };

    // Search Users
    useEffect(() => {
        if (searchQuery.length >= 3) {
            const delayDebounceFn = setTimeout(async () => {
                try {
                    const res = await api.get(`/contacts/search?query=${searchQuery}`);
                    setSearchResults(res.data);
                } catch (err) {
                    console.error("Search failed", err);
                }
            }, 300);
            return () => clearTimeout(delayDebounceFn);
        } else {
            setSearchResults([]);
        }
    }, [searchQuery]);

    // Fetch Chat History
    useEffect(() => {
        if (recipient) {
            const fetchHistory = async () => {
                try {
                    const response = await api.get(`/chat/history/${recipient.id}`);
                    setMessages(response.data);
                } catch (error) {
                    console.error("Failed to fetch history", error);
                }
            };
            fetchHistory();
        } else {
            setMessages([]);
        }
    }, [recipient]);

    // Scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const sendMessage = (e) => {
        e.preventDefault();
        if (!input.trim() || !recipient) return;

        socket.emit('send_message', {
            recipient_id: recipient.id,
            content: input,
            type: 'text'
        });

        setInput('');
    };

    const addContact = async (userId) => {
        try {
            await api.post('/contacts/', { contact_id: userId });
            fetchContacts();
            setSearchQuery('');
            setActiveTab('contacts');
        } catch (err) {
            alert(err.response?.data?.detail || "Failed to add contact");
        }
    };

    const handleFileSelect = async (e) => {
        const file = e.target.files[0];
        if (!file || !recipient) return;

        const formData = new FormData();
        formData.append('file', file);

        try {
            await api.post(`/chat/upload?recipient_id=${recipient.id}`, formData);
        } catch (error) {
            console.error("Upload failed", error);
            alert("File upload failed");
        }
    };

    return (
        <div className="flex h-screen bg-gray-100 overflow-hidden">
            {/* Sidebar */}
            <div className="w-80 bg-white border-r border-gray-200 flex flex-col shadow-lg z-10">
                {/* User Header */}
                <div className="p-4 border-b border-gray-200 bg-gray-50 flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 rounded-full bg-purple-100 flex items-center justify-center border border-purple-200">
                            <img
                                src={user?.profile_picture || `https://api.dicebear.com/7.x/initials/svg?seed=${user?.username}`}
                                alt="Profile"
                                className="w-full h-full rounded-full object-cover"
                            />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-gray-800 truncate w-32">{user?.full_name || user?.username}</h2>
                            <p className="text-xs text-green-500 flex items-center">
                                <span className="w-2 h-2 bg-green-500 rounded-full mr-1"></span>
                                Online
                            </p>
                        </div>
                    </div>
                    <div className="flex space-x-1">
                        <Link to="/dashboard" className="p-2 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-full transition" title="Security Dashboard">
                            <Activity className="w-5 h-5" />
                        </Link>
                        <Link to="/profile" className="p-2 text-gray-400 hover:text-purple-600 hover:bg-purple-50 rounded-full transition" title="My Profile">
                            <User className="w-5 h-5" />
                        </Link>
                        <button onClick={logout} className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-full transition" title="Logout">
                            <LogOut className="w-5 h-5" />
                        </button>
                    </div>
                </div>

                {/* Search & Tabs */}
                <div className="p-4 space-y-4">
                    <div className="relative">
                        <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
                        <input
                            type="text"
                            placeholder="Search users..."
                            className="w-full pl-10 pr-4 py-2 bg-gray-100 border-transparent focus:bg-white focus:border-purple-500 rounded-xl text-sm transition-all"
                            value={searchQuery}
                            onChange={(e) => {
                                setSearchQuery(e.target.value);
                                if (e.target.value) setActiveTab('search');
                                else setActiveTab('contacts');
                            }}
                        />
                    </div>

                    <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
                        <button
                            onClick={() => setActiveTab('contacts')}
                            className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all ${activeTab === 'contacts' ? 'bg-white shadow text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
                        >
                            Contacts
                        </button>
                        <button
                            onClick={() => setActiveTab('search')}
                            className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all ${activeTab === 'search' ? 'bg-white shadow text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
                        >
                            Global Search
                        </button>
                    </div>
                </div>

                {/* List Area */}
                <div className="flex-1 overflow-y-auto">
                    {activeTab === 'contacts' ? (
                        <div className="space-y-1 p-2">
                            {contacts.length === 0 ? (
                                <div className="text-center py-8 text-gray-400">
                                    <MessageSquare className="w-12 h-12 mx-auto mb-2 opacity-20" />
                                    <p className="text-sm">No contacts yet</p>
                                    <p className="text-xs">Search for users to add them</p>
                                </div>
                            ) : (
                                contacts.map((contact) => (
                                    <div
                                        key={contact.id}
                                        onClick={() => setRecipient(contact.contact_user)}
                                        className={`flex items-center p-3 rounded-xl cursor-pointer transition-all ${recipient?.id === contact.contact_user.id ? 'bg-purple-50 border-purple-100' : 'hover:bg-gray-50 border-transparent'} border`}
                                    >
                                        <div className="relative">
                                            <img
                                                src={contact.contact_user.profile_picture || `https://api.dicebear.com/7.x/initials/svg?seed=${contact.contact_user.username}`}
                                                alt=""
                                                className="w-10 h-10 rounded-full bg-gray-200 object-cover"
                                            />
                                            <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 border-2 border-white rounded-full"></div>
                                        </div>
                                        <div className="ml-3 flex-1 min-w-0">
                                            <div className="flex justify-between items-baseline">
                                                <h3 className="text-sm font-semibold text-gray-900 truncate">
                                                    {contact.alias || contact.contact_user.full_name || contact.contact_user.username}
                                                </h3>
                                            </div>
                                            <p className="text-xs text-gray-500 truncate">
                                                @{contact.contact_user.username}
                                            </p>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    ) : (
                        <div className="space-y-1 p-2">
                            {searchResults.map((user) => (
                                <div key={user.id} className="flex items-center justify-between p-3 hover:bg-gray-50 rounded-xl transition-colors group">
                                    <div className="flex items-center space-x-3">
                                        <img
                                            src={user.profile_picture || `https://api.dicebear.com/7.x/initials/svg?seed=${user.username}`}
                                            alt=""
                                            className="w-10 h-10 rounded-full bg-gray-200 object-cover"
                                        />
                                        <div>
                                            <h3 className="text-sm font-medium text-gray-900">{user.full_name || user.username}</h3>
                                            <p className="text-xs text-gray-500">@{user.username}</p>
                                        </div>
                                    </div>
                                    <button
                                        onClick={() => addContact(user.id)}
                                        className="p-2 text-purple-600 hover:bg-purple-100 rounded-full transition opacity-0 group-hover:opacity-100"
                                        title="Add to Contacts"
                                    >
                                        <UserPlus className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                            {searchQuery && searchResults.length === 0 && (
                                <div className="text-center py-4 text-gray-500 text-sm">No users found</div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Chat Area */}
            <div className="flex-1 flex flex-col bg-[#f0f2f5]">
                {recipient ? (
                    <>
                        {/* Chat Header */}
                        <div className="h-16 bg-white border-b border-gray-200 flex items-center justify-between px-6 shadow-sm z-10">
                            <div className="flex items-center">
                                <div className="w-10 h-10 rounded-full bg-gray-200 overflow-hidden">
                                    <img
                                        src={recipient.profile_picture || `https://api.dicebear.com/7.x/initials/svg?seed=${recipient.username}`}
                                        alt=""
                                        className="w-full h-full object-cover"
                                    />
                                </div>
                                <div className="ml-3">
                                    <h3 className="text-sm font-bold text-gray-900">{recipient.full_name || recipient.username}</h3>
                                    <div className="flex items-center text-xs text-green-600 bg-green-50 px-2 py-0.5 rounded-full w-fit mt-0.5">
                                        <ShieldCheck className="w-3 h-3 mr-1" />
                                        Quantum Secured (BB84 + Kyber)
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center space-x-4">
                                <button className="text-gray-400 hover:text-gray-600 transition">
                                    <MoreVertical className="w-5 h-5" />
                                </button>
                            </div>
                        </div>

                        {/* Messages */}
                        <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-[url('https://web.whatsapp.com/img/bg-chat-tile-dark_a4be512e7195b6b733d9110b408f9640.png')] bg-repeat bg-opacity-5">
                            {messages.map((msg, index) => {
                                const isMe = msg.sender_id === user.id;
                                let content = msg.content;
                                let isFile = false;
                                let fileUrl = "";

                                try {
                                    const parsed = JSON.parse(msg.content);
                                    if (parsed.download_url) {
                                        content = parsed.text;
                                        isFile = true;
                                        fileUrl = parsed.download_url;
                                    }
                                } catch (e) { }

                                return (
                                    <motion.div
                                        initial={{ opacity: 0, y: 10 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        key={index}
                                        className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}
                                    >
                                        <div className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg shadow-sm relative group ${isMe
                                            ? 'bg-purple-600 text-white rounded-br-none'
                                            : 'bg-white text-gray-900 rounded-bl-none'
                                            }`}>
                                            <p className="text-sm leading-relaxed">{content}</p>
                                            {isFile && (
                                                <a href={fileUrl} target="_blank" rel="noreferrer" className={`block mt-2 text-xs underline ${isMe ? 'text-purple-200' : 'text-purple-600'}`}>
                                                    Download Secure File
                                                </a>
                                            )}
                                            <div className={`text-[10px] mt-1 text-right flex items-center justify-end space-x-1 ${isMe ? 'text-purple-200' : 'text-gray-400'}`}>
                                                <span>{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                                                {isMe && (
                                                    <span>
                                                        {msg.read_at ? (
                                                            <span className="text-blue-300">✓✓</span>
                                                        ) : (
                                                            <span>✓</span>
                                                        )}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </motion.div>
                                );
                            })}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* Input Area */}
                        <div className="bg-white p-4 border-t border-gray-200">
                            <form onSubmit={sendMessage} className="flex items-center space-x-4 max-w-4xl mx-auto">
                                <input
                                    type="file"
                                    ref={fileInputRef}
                                    className="hidden"
                                    onChange={handleFileSelect}
                                />
                                <button type="button" onClick={() => fileInputRef.current.click()} className="text-gray-400 hover:text-purple-600 transition p-2 hover:bg-gray-100 rounded-full">
                                    <Paperclip className="w-5 h-5" />
                                </button>
                                <button type="button" className="text-gray-400 hover:text-purple-600 transition p-2 hover:bg-gray-100 rounded-full">
                                    <ImageIcon className="w-5 h-5" />
                                </button>
                                <input
                                    type="text"
                                    className="flex-1 bg-gray-100 border-transparent focus:bg-white focus:border-purple-500 focus:ring-0 rounded-full px-6 py-3 transition-all"
                                    placeholder="Type a secure message..."
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                />
                                <button
                                    type="submit"
                                    className="bg-purple-600 text-white p-3 rounded-full hover:bg-purple-700 transition shadow-lg disabled:opacity-50 disabled:cursor-not-allowed transform hover:scale-105 active:scale-95"
                                    disabled={!input.trim()}
                                >
                                    <Send className="w-5 h-5" />
                                </button>
                            </form>
                        </div>
                    </>
                ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-gray-500 bg-gray-50">
                        <div className="w-24 h-24 bg-purple-100 rounded-full flex items-center justify-center mb-6 animate-pulse">
                            <ShieldCheck className="w-12 h-12 text-purple-500" />
                        </div>
                        <h2 className="text-2xl font-bold text-gray-800 mb-2">Welcome to QuantumNet</h2>
                        <p className="text-center max-w-md mb-8">
                            Select a contact to start a quantum-secure conversation.
                            Your messages are protected by post-quantum cryptography.
                        </p>
                        <div className="flex items-center space-x-2 text-sm bg-white px-4 py-2 rounded-full shadow-sm border border-gray-200">
                            <Activity className="w-4 h-4 text-green-500" />
                            <span>System Status: <span className="font-semibold text-green-600">Secure & Online</span></span>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Chat;
