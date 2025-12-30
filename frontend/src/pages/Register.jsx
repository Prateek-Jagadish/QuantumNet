import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Lock, Sparkles, Key, ArrowRight, User } from 'lucide-react';

const Register = () => {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [fullName, setFullName] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const { register } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (password !== confirmPassword) {
            setError("Passwords do not match");
            return;
        }

        const result = await register(username, email, password, fullName);
        if (result.success) {
            navigate('/login');
        } else {
            setError(result.error);
        }
    };

    // Floating emojis and icons - More variety!
    const floatingElements = [
        { emoji: '🔐', delay: 0, x: '10%', y: '20%', size: 'text-4xl' },
        { emoji: '🛡️', delay: 0.5, x: '80%', y: '15%', size: 'text-5xl' },
        { emoji: '⚡', delay: 1, x: '15%', y: '70%', size: 'text-3xl' },
        { emoji: '🔑', delay: 1.5, x: '85%', y: '65%', size: 'text-4xl' },
        { emoji: '✨', delay: 2, x: '50%', y: '10%', size: 'text-3xl' },
        { emoji: '🌐', delay: 2.5, x: '90%', y: '40%', size: 'text-5xl' },
        { emoji: '💎', delay: 3, x: '5%', y: '45%', size: 'text-4xl' },
        { emoji: '🚀', delay: 0.8, x: '25%', y: '35%', size: 'text-3xl' },
        { emoji: '🔒', delay: 1.2, x: '70%', y: '50%', size: 'text-4xl' },
        { emoji: '💫', delay: 1.8, x: '40%', y: '75%', size: 'text-3xl' },
        { emoji: '🌟', delay: 2.2, x: '60%', y: '25%', size: 'text-4xl' },
        { emoji: '🎯', delay: 2.8, x: '12%', y: '55%', size: 'text-3xl' },
        { emoji: '🔮', delay: 0.3, x: '88%', y: '80%', size: 'text-5xl' },
        { emoji: '⭐', delay: 1.4, x: '35%', y: '12%', size: 'text-3xl' },
        { emoji: '🎨', delay: 2.1, x: '75%', y: '72%', size: 'text-4xl' },
        { emoji: '🌈', delay: 2.6, x: '20%', y: '85%', size: 'text-3xl' },
        { emoji: '🎭', delay: 0.6, x: '92%', y: '28%', size: 'text-4xl' },
        { emoji: '🎪', delay: 1.9, x: '8%', y: '62%', size: 'text-3xl' },
        { emoji: '🎬', delay: 2.4, x: '65%', y: '8%', size: 'text-4xl' },
        { emoji: '🎸', delay: 2.9, x: '45%', y: '90%', size: 'text-3xl' },
    ];

    return (
        <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-purple-50 via-white to-sky-50">
            {/* Animated Background Pattern */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                {/* Floating gradient orbs */}
                <motion.div
                    animate={{
                        scale: [1, 1.2, 1],
                        x: [0, 50, 0],
                        y: [0, -30, 0],
                    }}
                    transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
                    className="absolute top-20 left-10 w-72 h-72 bg-purple-300/30 rounded-full blur-3xl"
                />
                <motion.div
                    animate={{
                        scale: [1, 1.3, 1],
                        x: [0, -50, 0],
                        y: [0, 50, 0],
                    }}
                    transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
                    className="absolute bottom-20 right-10 w-96 h-96 bg-sky-300/30 rounded-full blur-3xl"
                />

                {/* Decorative lines pattern */}
                {/* Animated dots pattern */}
                <div className="absolute inset-0">
                    {[...Array(30)].map((_, i) => (
                        <motion.div
                            key={i}
                            className="absolute w-2 h-2 bg-purple-400/20 rounded-full"
                            style={{
                                left: `${Math.random() * 100}%`,
                                top: `${Math.random() * 100}%`,
                            }}
                            animate={{
                                scale: [1, 1.5, 1],
                                opacity: [0.2, 0.5, 0.2],
                            }}
                            transition={{
                                duration: 3 + Math.random() * 2,
                                repeat: Infinity,
                                delay: Math.random() * 2,
                            }}
                        />
                    ))}
                </div>

                <svg className="absolute inset-0 w-full h-full opacity-10" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-purple-500" />
                        </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#grid)" />
                </svg>

                {/* Floating emojis */}
                {floatingElements.map((item, index) => (
                    <motion.div
                        key={index}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{
                            opacity: [0.3, 0.6, 0.3],
                            y: [0, -20, 0],
                            rotate: [0, 10, -10, 0],
                        }}
                        transition={{
                            duration: 4,
                            delay: item.delay,
                            repeat: Infinity,
                            ease: "easeInOut"
                        }}
                        className={`absolute ${item.size}`}
                        style={{ left: item.x, top: item.y }}
                    >
                        {item.emoji}
                    </motion.div>
                ))}

                {/* Sparkle effects */}
                {[...Array(15)].map((_, i) => (
                    <motion.div
                        key={`sparkle-${i}`}
                        className="absolute text-yellow-400"
                        style={{
                            left: `${Math.random() * 100}%`,
                            top: `${Math.random() * 100}%`,
                        }}
                        animate={{
                            opacity: [0, 1, 0],
                            scale: [0, 1, 0],
                            rotate: [0, 180, 360],
                        }}
                        transition={{
                            duration: 2 + Math.random(),
                            repeat: Infinity,
                            delay: Math.random() * 3,
                        }}
                    >
                        ✨
                    </motion.div>
                ))}
            </div>

            {/* Main Content */}
            <div className="relative z-10 min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6 }}
                    className="max-w-md w-full"
                >
                    {/* Logo/Brand */}
                    <motion.div
                        initial={{ scale: 0.8 }}
                        animate={{ scale: 1 }}
                        transition={{ duration: 0.5 }}
                        className="text-center mb-8"
                    >
                        <motion.div
                            animate={{ rotate: [0, 5, -5, 0] }}
                            transition={{ duration: 3, repeat: Infinity }}
                            className="inline-block"
                        >
                            <Shield className="h-16 w-16 text-purple-600 mx-auto mb-4" />
                        </motion.div>
                        <h2 className="text-4xl font-extrabold">
                            <span className="bg-clip-text text-transparent bg-gradient-to-r from-purple-600 to-sky-500">
                                Join QuantumNet
                            </span>
                        </h2>
                        <p className="mt-2 text-gray-600">
                            Create your quantum-secure identity
                        </p>
                    </motion.div>

                    {/* Registration Card */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ duration: 0.5, delay: 0.2 }}
                        className="relative bg-white/90 backdrop-blur-xl rounded-3xl shadow-2xl border-2 border-purple-200/50 overflow-hidden"
                        style={{
                            boxShadow: '0 20px 60px -15px rgba(124, 58, 237, 0.3), 0 0 0 1px rgba(124, 58, 237, 0.1)'
                        }}
                    >
                        {/* Decorative corner elements */}
                        <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-purple-400/20 to-transparent rounded-bl-full" />
                        <div className="absolute bottom-0 left-0 w-40 h-40 bg-gradient-to-tr from-sky-400/20 to-transparent rounded-tr-full" />
                        <div className="absolute top-0 left-0 w-32 h-32 bg-gradient-to-br from-sky-300/10 to-transparent rounded-br-full" />
                        <div className="absolute bottom-0 right-0 w-32 h-32 bg-gradient-to-tl from-purple-300/10 to-transparent rounded-tl-full" />

                        {/* Animated border glow */}
                        <motion.div
                            className="absolute inset-0 rounded-3xl"
                            animate={{
                                boxShadow: [
                                    '0 0 20px rgba(124, 58, 237, 0.3)',
                                    '0 0 40px rgba(59, 130, 246, 0.3)',
                                    '0 0 20px rgba(124, 58, 237, 0.3)',
                                ]
                            }}
                            transition={{ duration: 3, repeat: Infinity }}
                        />

                        {/* Card Content */}
                        <div className="relative p-8">
                            <form onSubmit={handleSubmit} className="space-y-6">
                                {/* Full Name Field */}
                                <motion.div
                                    initial={{ x: -20, opacity: 0 }}
                                    animate={{ x: 0, opacity: 1 }}
                                    transition={{ delay: 0.2 }}
                                >
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Full Name
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <User className="h-5 w-5 text-purple-400" />
                                        </div>
                                        <input
                                            type="text"
                                            className="block w-full pl-10 pr-3 py-3 border border-purple-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 bg-white/50"
                                            placeholder="John Doe"
                                            value={fullName}
                                            onChange={(e) => setFullName(e.target.value)}
                                        />
                                    </div>
                                </motion.div>

                                {/* Email Field */}
                                <motion.div
                                    initial={{ x: -20, opacity: 0 }}
                                    animate={{ x: 0, opacity: 1 }}
                                    transition={{ delay: 0.25 }}
                                >
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Email Address
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <span className="text-lg">📧</span>
                                        </div>
                                        <input
                                            type="email"
                                            required
                                            className="block w-full pl-10 pr-3 py-3 border border-purple-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 bg-white/50"
                                            placeholder="you@example.com"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                        />
                                    </div>
                                </motion.div>

                                {/* Username Field */}
                                <motion.div
                                    initial={{ x: -20, opacity: 0 }}
                                    animate={{ x: 0, opacity: 1 }}
                                    transition={{ delay: 0.3 }}
                                >
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Username
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <User className="h-5 w-5 text-purple-400" />
                                        </div>
                                        <input
                                            type="text"
                                            required
                                            className="block w-full pl-10 pr-3 py-3 border border-purple-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 bg-white/50"
                                            placeholder="Choose a username"
                                            value={username}
                                            onChange={(e) => setUsername(e.target.value)}
                                        />
                                    </div>
                                </motion.div>

                                {/* Password Field */}
                                <motion.div
                                    initial={{ x: -20, opacity: 0 }}
                                    animate={{ x: 0, opacity: 1 }}
                                    transition={{ delay: 0.4 }}
                                >
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Password
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <Lock className="h-5 w-5 text-purple-400" />
                                        </div>
                                        <input
                                            type="password"
                                            required
                                            className="block w-full pl-10 pr-3 py-3 border border-purple-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 bg-white/50"
                                            placeholder="Create a strong password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                        />
                                    </div>
                                </motion.div>

                                {/* Confirm Password Field */}
                                <motion.div
                                    initial={{ x: -20, opacity: 0 }}
                                    animate={{ x: 0, opacity: 1 }}
                                    transition={{ delay: 0.45 }}
                                >
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Confirm Password
                                    </label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <Lock className="h-5 w-5 text-purple-400" />
                                        </div>
                                        <input
                                            type="password"
                                            required
                                            className="block w-full pl-10 pr-3 py-3 border border-purple-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 bg-white/50"
                                            placeholder="Confirm your password"
                                            value={confirmPassword}
                                            onChange={(e) => setConfirmPassword(e.target.value)}
                                        />
                                    </div>
                                </motion.div>

                                {/* Error Message */}
                                {error && (
                                    <motion.div
                                        initial={{ opacity: 0, y: -10 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm"
                                    >
                                        {error}
                                    </motion.div>
                                )}

                                {/* Submit Button */}
                                <motion.div
                                    initial={{ y: 20, opacity: 0 }}
                                    animate={{ y: 0, opacity: 1 }}
                                    transition={{ delay: 0.5 }}
                                >
                                    <motion.button
                                        whileHover={{ scale: 1.02, y: -2 }}
                                        whileTap={{ scale: 0.98 }}
                                        type="submit"
                                        className="group relative w-full flex items-center justify-center py-3 px-4 border border-transparent text-base font-medium rounded-xl text-white bg-gradient-to-r from-purple-600 to-sky-500 hover:shadow-xl transition-all duration-300"
                                    >
                                        <Key className="h-5 w-5 mr-2" />
                                        Register & Generate Keys
                                        <motion.div
                                            animate={{ x: [0, 5, 0] }}
                                            transition={{ duration: 1.5, repeat: Infinity }}
                                            className="ml-2"
                                        >
                                            <ArrowRight className="h-5 w-5" />
                                        </motion.div>
                                    </motion.button>
                                </motion.div>

                                {/* Security Badge */}
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 0.6 }}
                                    className="flex items-center justify-center space-x-2 text-sm text-gray-500"
                                >
                                    <Sparkles className="h-4 w-4 text-purple-500" />
                                    <span>Quantum-safe encryption enabled</span>
                                </motion.div>

                                {/* Login Link */}
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 0.7 }}
                                    className="text-center pt-4 border-t border-purple-100"
                                >
                                    <Link
                                        to="/login"
                                        className="text-sm font-medium text-purple-600 hover:text-purple-500 transition-colors"
                                    >
                                        Already have an account? <span className="underline">Sign in</span>
                                    </Link>
                                </motion.div>
                            </form>
                        </div>
                    </motion.div>

                    {/* Back to Home */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.8 }}
                        className="text-center mt-6"
                    >
                        <Link
                            to="/"
                            className="text-sm text-gray-600 hover:text-purple-600 transition-colors"
                        >
                            ← Back to home
                        </Link>
                    </motion.div>
                </motion.div>
            </div>
        </div>
    );
};

export default Register;