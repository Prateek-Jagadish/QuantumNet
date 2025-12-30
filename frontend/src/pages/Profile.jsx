import React, { useState, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { User, Mail, Hash, Camera, ArrowLeft, Shield, Save } from 'lucide-react';
import { Link } from 'react-router-dom';

const Profile = () => {
    const { user } = useAuth();
    const [isEditing, setIsEditing] = useState(false);
    // In a real app, we would have update logic here. For now, it's read-only/mock.

    const fileInputRef = useRef(null);

    const handleImageClick = () => {
        fileInputRef.current.click();
    };

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            // In a real app, upload to server
            alert("Profile picture upload would happen here in production!");
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl mx-auto">
                {/* Header */}
                <div className="mb-8 flex items-center justify-between">
                    <Link to="/chat" className="flex items-center text-gray-600 hover:text-purple-600 transition">
                        <ArrowLeft className="w-5 h-5 mr-2" />
                        Back to Chat
                    </Link>
                    <h1 className="text-2xl font-bold text-gray-900">My Profile</h1>
                </div>

                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-white rounded-2xl shadow-xl overflow-hidden"
                >
                    {/* Banner */}
                    <div className="h-32 bg-gradient-to-r from-purple-600 to-blue-500 relative">
                        <div className="absolute inset-0 bg-black/10" />
                    </div>

                    <div className="px-8 pb-8">
                        {/* Avatar Section */}
                        <div className="relative -mt-16 mb-6 flex justify-center sm:justify-start">
                            <div className="relative group">
                                <div className="w-32 h-32 rounded-full border-4 border-white shadow-lg overflow-hidden bg-white">
                                    <img
                                        src={user?.profile_picture || `https://api.dicebear.com/7.x/initials/svg?seed=${user?.username}`}
                                        alt="Profile"
                                        className="w-full h-full object-cover"
                                    />
                                </div>
                                <button
                                    onClick={handleImageClick}
                                    className="absolute bottom-0 right-0 bg-purple-600 text-white p-2 rounded-full shadow-lg hover:bg-purple-700 transition group-hover:scale-110"
                                >
                                    <Camera className="w-4 h-4" />
                                </button>
                                <input
                                    type="file"
                                    ref={fileInputRef}
                                    className="hidden"
                                    accept="image/*"
                                    onChange={handleFileChange}
                                />
                            </div>
                        </div>

                        {/* User Details */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <div className="space-y-6">
                                <div>
                                    <label className="block text-sm font-medium text-gray-500 mb-1">Full Name</label>
                                    <div className="flex items-center space-x-3 text-gray-900 text-lg font-medium p-3 bg-gray-50 rounded-lg">
                                        <User className="w-5 h-5 text-purple-500" />
                                        <span>{user?.full_name || "Not set"}</span>
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-500 mb-1">Username</label>
                                    <div className="flex items-center space-x-3 text-gray-900 text-lg font-medium p-3 bg-gray-50 rounded-lg">
                                        <span className="text-purple-500 font-bold">@</span>
                                        <span>{user?.username}</span>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-6">
                                <div>
                                    <label className="block text-sm font-medium text-gray-500 mb-1">Email Address</label>
                                    <div className="flex items-center space-x-3 text-gray-900 text-lg font-medium p-3 bg-gray-50 rounded-lg">
                                        <Mail className="w-5 h-5 text-purple-500" />
                                        <span>{user?.email || "No email"}</span>
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-500 mb-1">User ID</label>
                                    <div className="flex items-center space-x-3 text-gray-600 font-mono text-sm p-3 bg-gray-50 rounded-lg break-all">
                                        <Hash className="w-4 h-4 text-purple-500 flex-shrink-0" />
                                        <span>{user?.id}</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Security Badge */}
                        <div className="mt-8 pt-6 border-t border-gray-100">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center space-x-2 text-green-600 bg-green-50 px-4 py-2 rounded-full">
                                    <Shield className="w-5 h-5" />
                                    <span className="font-medium">Quantum Security Active</span>
                                </div>
                                <div className="text-sm text-gray-500">
                                    Keys managed by Kyber-768
                                </div>
                            </div>
                        </div>
                    </div>
                </motion.div>
            </div>
        </div>
    );
};

export default Profile;
