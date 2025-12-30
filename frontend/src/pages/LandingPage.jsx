import React, { useRef } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Lock, Zap, ChevronRight, Check, Sparkles } from 'lucide-react';
import { motion, useInView, useScroll, useTransform } from 'framer-motion';

const LandingPage = () => {
    const heroRef = useRef(null);
    const featuresRef = useRef(null);
    const { scrollY } = useScroll();

    const heroInView = useInView(heroRef, { once: true, margin: "-100px" });
    const featuresInView = useInView(featuresRef, { once: true, margin: "-100px" });

    // Parallax effects - move content at different speeds
    const heroY = useTransform(scrollY, [0, 500], [0, 150]);
    const imageY = useTransform(scrollY, [0, 500], [0, -100]);

    return (
        <div className="min-h-screen bg-gradient-to-br from-white via-purple-50/30 to-sky-50/50 text-gray-900 font-sans overflow-x-hidden">
            {/* Floating Background Elements */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none">
                <motion.div
                    animate={{
                        x: [0, 100, 0],
                        y: [0, -100, 0],
                    }}
                    transition={{
                        duration: 20,
                        repeat: Infinity,
                        ease: "linear"
                    }}
                    className="absolute top-20 left-10 w-72 h-72 bg-purple-200/20 rounded-full blur-3xl"
                />
                <motion.div
                    animate={{
                        x: [0, -100, 0],
                        y: [0, 100, 0],
                    }}
                    transition={{
                        duration: 25,
                        repeat: Infinity,
                        ease: "linear"
                    }}
                    className="absolute bottom-20 right-10 w-96 h-96 bg-sky-200/20 rounded-full blur-3xl"
                />
            </div>

            {/* Navbar */}
            <motion.nav
                initial={{ y: -100 }}
                animate={{ y: 0 }}
                className="fixed w-full z-50 bg-white/80 backdrop-blur-xl border-b border-purple-100/50 shadow-sm"
            >
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        <motion.div
                            className="flex items-center"
                            whileHover={{ scale: 1.05 }}
                        >
                            <Shield className="h-8 w-8 text-purple-600" />
                            <span className="ml-2 text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-600 to-sky-500">
                                QuantumNet
                            </span>
                        </motion.div>
                        <div className="hidden md:flex items-center space-x-4">
                            <Link to="/about" className="text-sm font-medium text-gray-600 hover:text-purple-600 transition-colors">
                                About
                            </Link>
                            <Link to="/contact" className="text-sm font-medium text-gray-600 hover:text-purple-600 transition-colors">
                                Contact
                            </Link>
                            <Link to="/demo">
                                <motion.button
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                    className="px-6 py-2 rounded-full text-sm font-medium text-sky-600 hover:bg-sky-50 transition-colors flex items-center"
                                >
                                    <Sparkles className="w-4 h-4 mr-1" />
                                    Live Demo
                                </motion.button>
                            </Link>
                            <Link to="/login">
                                <motion.button
                                    whileHover={{ scale: 1.05 }}
                                    whileTap={{ scale: 0.95 }}
                                    className="px-6 py-2 rounded-full text-sm font-medium text-purple-600 hover:bg-purple-50 transition-colors"
                                >
                                    Login
                                </motion.button>
                            </Link>
                            <Link to="/register">
                                <motion.button
                                    whileHover={{ scale: 1.05, boxShadow: "0 10px 30px -10px rgba(124, 58, 237, 0.5)" }}
                                    whileTap={{ scale: 0.95 }}
                                    className="bg-gradient-to-r from-purple-600 to-sky-500 px-6 py-2 rounded-full text-sm font-medium text-white shadow-lg"
                                >
                                    Get Started
                                </motion.button>
                            </Link>
                        </div>
                    </div>
                </div>
            </motion.nav>

            {/* Hero Section */}
            <div
                ref={heroRef}
                className="relative pt-32 pb-20 sm:pt-40 sm:pb-32 overflow-hidden"
            >
                <motion.div
                    style={{ y: heroY }}
                    className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center"
                >
                    <motion.div
                        initial={{ opacity: 0, y: 30 }}
                        animate={heroInView ? { opacity: 1, y: 0 } : {}}
                        transition={{ duration: 0.8 }}
                    >
                        <motion.div
                            animate={{ rotate: [0, 5, 0, -5, 0] }}
                            transition={{ duration: 5, repeat: Infinity }}
                            className="inline-block mb-6"
                        >
                            <Sparkles className="h-12 w-12 text-purple-500 mx-auto" />
                        </motion.div>

                        <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-8 leading-tight">
                            <span className="block text-gray-900">The Future of</span>
                            <motion.span
                                className="block bg-clip-text text-transparent bg-gradient-to-r from-purple-600 via-purple-500 to-sky-500"
                                animate={{
                                    backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'],
                                }}
                                transition={{ duration: 5, repeat: Infinity }}
                                style={{ backgroundSize: '200% 200%' }}
                            >
                                Quantum-Secure Chat
                            </motion.span>
                        </h1>
                    </motion.div>

                    <motion.p
                        initial={{ opacity: 0, y: 20 }}
                        animate={heroInView ? { opacity: 1, y: 0 } : {}}
                        transition={{ duration: 0.8, delay: 0.2 }}
                        className="mt-6 max-w-3xl mx-auto text-xl text-gray-600 mb-12"
                    >
                        Experience unbreakable security with BB84 Quantum Key Distribution,
                        Post-Quantum Cryptography, and military-grade encryption.
                    </motion.p>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={heroInView ? { opacity: 1, y: 0 } : {}}
                        transition={{ duration: 0.8, delay: 0.4 }}
                        className="flex justify-center gap-4 flex-wrap"
                    >
                        <Link to="/register">
                            <motion.button
                                whileHover={{ scale: 1.05, y: -2 }}
                                whileTap={{ scale: 0.95 }}
                                className="group relative inline-flex items-center justify-center px-8 py-4 text-base font-medium text-white bg-gradient-to-r from-purple-600 to-sky-500 rounded-full shadow-xl hover:shadow-2xl transition-all duration-300"
                            >
                                Experience the Technology
                                <motion.div
                                    animate={{ x: [0, 5, 0] }}
                                    transition={{ duration: 1.5, repeat: Infinity }}
                                >
                                    <ChevronRight className="ml-2 h-5 w-5" />
                                </motion.div>
                            </motion.button>
                        </Link>
                        <Link to="/demo">
                            <motion.button
                                whileHover={{ scale: 1.05, y: -2, boxShadow: "0 20px 40px -10px rgba(124, 58, 237, 0.4)" }}
                                whileTap={{ scale: 0.95 }}
                                className="inline-flex items-center justify-center px-8 py-4 text-base font-medium text-purple-600 bg-gradient-to-r from-purple-50 to-sky-50 border-2 border-purple-300 rounded-full shadow-lg hover:shadow-xl transition-all duration-300"
                            >
                                <Sparkles className="mr-2 h-5 w-5" />
                                Try Live Demo
                            </motion.button>
                        </Link>
                        <Link to="/login">
                            <motion.button
                                whileHover={{ scale: 1.05, y: -2 }}
                                whileTap={{ scale: 0.95 }}
                                className="inline-flex items-center justify-center px-8 py-4 text-base font-medium text-purple-600 bg-white border-2 border-purple-200 rounded-full shadow-lg hover:shadow-xl hover:border-purple-300 transition-all duration-300"
                            >
                                Login
                            </motion.button>
                        </Link>
                    </motion.div>
                </motion.div>

                {/* Animated Hero Image */}
                <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={heroInView ? { opacity: 1, scale: 1 } : {}}
                    transition={{ duration: 1, delay: 0.6 }}
                    style={{ y: imageY }}
                    className="relative max-w-5xl mx-auto mt-16 px-4"
                >
                    <motion.div
                        animate={{ y: [0, -20, 0] }}
                        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                        className="relative"
                    >
                        <img
                            src="/assets/hero-bg.png"
                            alt="Quantum Network"
                            className="w-full rounded-3xl shadow-2xl"
                        />
                        <div className="absolute inset-0 bg-gradient-to-t from-white via-transparent to-transparent rounded-3xl"></div>
                    </motion.div>
                </motion.div>
            </div>

            {/* Core Technologies */}
            <div ref={featuresRef} className="py-20 relative">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <motion.div
                        initial={{ opacity: 0, y: 30 }}
                        animate={featuresInView ? { opacity: 1, y: 0 } : {}}
                        transition={{ duration: 0.8 }}
                        className="text-center mb-16"
                    >
                        <h2 className="text-4xl md:text-5xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-purple-600 to-sky-500">
                            Triple-Layer Security
                        </h2>
                        <p className="text-gray-600 max-w-2xl mx-auto text-lg">
                            Physics meets mathematics to create the most secure communication system ever built.
                        </p>
                    </motion.div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                        {/* QKD Card */}
                        <motion.div
                            initial={{ opacity: 0, y: 50 }}
                            animate={featuresInView ? { opacity: 1, y: 0 } : {}}
                            transition={{ duration: 0.6, delay: 0.1 }}
                            whileHover={{ y: -10, scale: 1.02 }}
                            className="group relative bg-white rounded-3xl overflow-hidden shadow-lg hover:shadow-2xl transition-all duration-300 border border-purple-100"
                        >
                            <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-purple-400/20 to-transparent rounded-bl-full"></div>

                            <div className="relative h-56 overflow-hidden bg-gradient-to-br from-purple-50 to-white">
                                <motion.img
                                    whileHover={{ scale: 1.1, rotate: 2 }}
                                    transition={{ duration: 0.4 }}
                                    src="/assets/qkd.png"
                                    alt="QKD"
                                    className="w-full h-full object-cover"
                                />
                            </div>

                            <div className="p-8">
                                <div className="flex items-center mb-4">
                                    <div className="p-2 bg-purple-100 rounded-lg">
                                        <Zap className="h-6 w-6 text-purple-600" />
                                    </div>
                                    <h3 className="ml-3 text-2xl font-bold text-gray-900">BB84 QKD</h3>
                                </div>
                                <p className="text-gray-600 mb-6 leading-relaxed">
                                    Leverages quantum mechanics to generate unhackable keys.
                                    Any eavesdropping attempt instantly alerts the system.
                                </p>
                                <ul className="space-y-3">
                                    <li className="flex items-center text-gray-700">
                                        <Check className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                                        Physics-based security
                                    </li>
                                    <li className="flex items-center text-gray-700">
                                        <Check className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                                        Instant threat detection
                                    </li>
                                </ul>
                            </div>
                        </motion.div>

                        {/* Kyber Card */}
                        <motion.div
                            initial={{ opacity: 0, y: 50 }}
                            animate={featuresInView ? { opacity: 1, y: 0 } : {}}
                            transition={{ duration: 0.6, delay: 0.2 }}
                            whileHover={{ y: -10, scale: 1.02 }}
                            className="group relative bg-white rounded-3xl overflow-hidden shadow-lg hover:shadow-2xl transition-all duration-300 border border-sky-100"
                        >
                            <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-sky-400/20 to-transparent rounded-bl-full"></div>

                            <div className="relative h-56 overflow-hidden bg-gradient-to-br from-sky-50 to-white">
                                <motion.img
                                    whileHover={{ scale: 1.1, rotate: -2 }}
                                    transition={{ duration: 0.4 }}
                                    src="/assets/kyber.png"
                                    alt="Kyber"
                                    className="w-full h-full object-cover"
                                />
                            </div>

                            <div className="p-8">
                                <div className="flex items-center mb-4">
                                    <div className="p-2 bg-sky-100 rounded-lg">
                                        <Shield className="h-6 w-6 text-sky-600" />
                                    </div>
                                    <h3 className="ml-3 text-2xl font-bold text-gray-900">CRYSTALS-Kyber</h3>
                                </div>
                                <p className="text-gray-600 mb-6 leading-relaxed">
                                    NIST-approved quantum-resistant encryption that withstands
                                    even the most powerful quantum computers.
                                </p>
                                <ul className="space-y-3">
                                    <li className="flex items-center text-gray-700">
                                        <Check className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                                        Future-proof cryptography
                                    </li>
                                    <li className="flex items-center text-gray-700">
                                        <Check className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                                        Global standard
                                    </li>
                                </ul>
                            </div>
                        </motion.div>

                        {/* AES Card */}
                        <motion.div
                            initial={{ opacity: 0, y: 50 }}
                            animate={featuresInView ? { opacity: 1, y: 0 } : {}}
                            transition={{ duration: 0.6, delay: 0.3 }}
                            whileHover={{ y: -10, scale: 1.02 }}
                            className="group relative bg-white rounded-3xl overflow-hidden shadow-lg hover:shadow-2xl transition-all duration-300 border border-purple-100"
                        >
                            <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-purple-400/20 to-transparent rounded-bl-full"></div>

                            <div className="relative h-56 overflow-hidden bg-gradient-to-br from-purple-50 to-white">
                                <motion.img
                                    whileHover={{ scale: 1.1, rotate: 2 }}
                                    transition={{ duration: 0.4 }}
                                    src="/assets/aes.png"
                                    alt="AES"
                                    className="w-full h-full object-cover"
                                />
                            </div>

                            <div className="p-8">
                                <div className="flex items-center mb-4">
                                    <div className="p-2 bg-purple-100 rounded-lg">
                                        <Lock className="h-6 w-6 text-purple-600" />
                                    </div>
                                    <h3 className="ml-3 text-2xl font-bold text-gray-900">AES-256-GCM</h3>
                                </div>
                                <p className="text-gray-600 mb-6 leading-relaxed">
                                    Military-grade encryption with built-in authentication
                                    ensures every message is tamper-proof.
                                </p>
                                <ul className="space-y-3">
                                    <li className="flex items-center text-gray-700">
                                        <Check className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                                        Bank-level security
                                    </li>
                                    <li className="flex items-center text-gray-700">
                                        <Check className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                                        Integrity verified
                                    </li>
                                </ul>
                            </div>
                        </motion.div>
                    </div>
                </div>
            </div>

            {/* CTA Section */}
            <div className="py-20 relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-sky-500 opacity-95"></div>
                <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 50, repeat: Infinity, ease: "linear" }}
                    className="absolute -top-40 -right-40 w-96 h-96 bg-white/10 rounded-full blur-3xl"
                />
                <motion.div
                    animate={{ rotate: -360 }}
                    transition={{ duration: 40, repeat: Infinity, ease: "linear" }}
                    className="absolute -bottom-40 -left-40 w-96 h-96 bg-white/10 rounded-full blur-3xl"
                />

                <div className="relative max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
                    <motion.h2
                        initial={{ opacity: 0, y: 30 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        className="text-4xl md:text-5xl font-bold text-white mb-6"
                    >
                        Ready to Experience True Privacy?
                    </motion.h2>
                    <motion.p
                        initial={{ opacity: 0, y: 20 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        transition={{ delay: 0.2 }}
                        className="text-xl text-white/90 mb-10"
                    >
                        Join the quantum revolution and protect your conversations with unbreakable encryption.
                    </motion.p>
                    <Link to="/register">
                        <motion.button
                            whileHover={{ scale: 1.05, y: -2 }}
                            whileTap={{ scale: 0.95 }}
                            className="px-10 py-4 bg-white text-purple-600 rounded-full text-lg font-semibold shadow-2xl hover:shadow-white/20 transition-all duration-300"
                        >
                            Get Started Free
                        </motion.button>
                    </Link>
                </div>
            </div>

            {/* Footer */}
            <footer className="bg-white border-t border-purple-100 py-12">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center">
                    <div className="flex items-center mb-4 md:mb-0">
                        <Shield className="h-6 w-6 text-purple-600" />
                        <span className="ml-2 text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-600 to-sky-500">
                            QuantumNet
                        </span>
                    </div>
                    <div className="flex space-x-6 text-sm text-gray-500">
                        <Link to="/about" className="hover:text-purple-600 transition">About</Link>
                        <Link to="/contact" className="hover:text-purple-600 transition">Contact</Link>
                        <Link to="/demo" className="hover:text-purple-600 transition">Demo</Link>
                    </div>
                    <div className="text-gray-500 text-sm mt-4 md:mt-0">
                        © 2025 QuantumNet. Research-grade secure communication.
                    </div>
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
