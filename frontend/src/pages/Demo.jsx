import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowLeft, Play, RotateCcw, ChevronRight, Lock, Unlock, Key, Shield, Zap, CheckCircle, Radio, Cpu, Send, Eye, Terminal } from 'lucide-react';

const Demo = () => {
    const [activeTab, setActiveTab] = useState('step-by-step'); // 'step-by-step' or 'live-simulation'

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 via-purple-50 to-blue-50 p-6">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <header className="mb-8">
                    <Link to="/" className="inline-flex items-center text-blue-600 hover:text-blue-700 mb-4 transition">
                        <ArrowLeft className="w-4 h-4 mr-2" />
                        Back to Home
                    </Link>
                    <div className="flex items-center justify-between">
                        <div>
                            <h1 className="text-4xl font-bold text-gray-900 mb-2">Live Quantum Encryption Demo</h1>
                            <p className="text-gray-600">Interactive demonstration of the complete encryption pipeline</p>
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="flex space-x-4 mt-6 border-b border-gray-200">
                        <button
                            onClick={() => setActiveTab('step-by-step')}
                            className={`pb-3 px-4 text-sm font-medium transition-colors relative ${activeTab === 'step-by-step' ? 'text-purple-600' : 'text-gray-500 hover:text-gray-700'
                                }`}
                        >
                            Step-by-Step Animation
                            {activeTab === 'step-by-step' && (
                                <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-600" />
                            )}
                        </button>
                        <button
                            onClick={() => setActiveTab('live-simulation')}
                            className={`pb-3 px-4 text-sm font-medium transition-colors relative ${activeTab === 'live-simulation' ? 'text-purple-600' : 'text-gray-500 hover:text-gray-700'
                                }`}
                        >
                            Live Simulation (Inspector)
                            {activeTab === 'live-simulation' && (
                                <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-600" />
                            )}
                        </button>
                    </div>
                </header>

                {activeTab === 'step-by-step' ? <StepByStepDemo /> : <LiveSimulationDemo />}
            </div>
        </div>
    );
};

const StepByStepDemo = () => {
    const [currentStep, setCurrentStep] = useState(0);
    const [isRunning, setIsRunning] = useState(false);
    const [message, setMessage] = useState('Hello, Quantum World!');
    const [bb84Key, setBb84Key] = useState('');
    const [kyberKey, setKyberKey] = useState('');
    const [hybridKey, setHybridKey] = useState('');
    const [encryptedMessage, setEncryptedMessage] = useState('');
    const [decryptedMessage, setDecryptedMessage] = useState('');
    const [completedSteps, setCompletedSteps] = useState([]);

    const steps = [
        {
            id: 0,
            title: 'BB84 Quantum Key Distribution',
            subtitle: 'Alice sends photons to Bob',
            description: 'Alice generates random bits and encodes them in photon polarization states. Bob measures the photons using random bases. They compare bases publicly and keep matching results as the shared key.',
            icon: Radio,
            color: 'from-purple-500 to-pink-500',
            action: () => {
                const key = Array.from({ length: 32 }, () => Math.random() > 0.5 ? '1' : '0').join('');
                setBb84Key(key);
            }
        },
        {
            id: 1,
            title: 'Kyber Post-Quantum Key Exchange',
            subtitle: 'Lattice-based cryptography',
            description: 'Using CRYSTALS-Kyber algorithm, Alice and Bob establish a quantum-resistant shared secret based on the hardness of lattice problems. This protects against future quantum computer attacks.',
            icon: Shield,
            color: 'from-blue-500 to-cyan-500',
            action: () => {
                const key = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
                setKyberKey(key);
            }
        },
        {
            id: 2,
            title: 'Hybrid Key Derivation',
            subtitle: 'Combining quantum and post-quantum keys',
            description: 'The BB84 quantum key and Kyber key are combined using a key derivation function (KDF) to create a master encryption key that benefits from both quantum and post-quantum security.',
            icon: Key,
            color: 'from-indigo-500 to-purple-500',
            action: () => {
                // Simulate KDF (SHA-256 of concatenated keys)
                const combined = bb84Key + kyberKey;
                const hybridKeySimulated = Array.from({ length: 64 }, (_, i) =>
                    Math.floor((combined.charCodeAt(i % combined.length) * (i + 1)) % 16).toString(16)
                ).join('');
                setHybridKey(hybridKeySimulated);
            }
        },
        {
            id: 3,
            title: 'AES-256-GCM Encryption',
            subtitle: 'Military-grade symmetric encryption',
            description: 'The message is encrypted using AES-256 in GCM mode with the derived hybrid key. GCM provides both confidentiality and authentication, ensuring the message cannot be read or tampered with.',
            icon: Lock,
            color: 'from-green-500 to-emerald-500',
            action: () => {
                const encrypted = btoa(message).split('').map(c =>
                    String.fromCharCode(c.charCodeAt(0) + Math.floor(Math.random() * 10))
                ).join('');
                setEncryptedMessage(encrypted);
            }
        },
        {
            id: 4,
            title: 'Secure Transmission',
            subtitle: 'Sending encrypted data',
            description: 'The encrypted message is transmitted over the network. Even if intercepted, the ciphertext is useless without the hybrid quantum-resistant key.',
            icon: Send,
            color: 'from-yellow-500 to-orange-500',
            action: () => {
                // Simulated transmission
            }
        },
        {
            id: 5,
            title: 'Message Decryption',
            subtitle: 'Bob decrypts the message',
            description: 'Using the same hybrid key derived from BB84 and Kyber, Bob decrypts the message with AES-256-GCM. The authentication tag is verified to ensure the message was not tampered with.',
            icon: Unlock,
            color: 'from-red-500 to-pink-500',
            action: () => {
                setDecryptedMessage(message);
            }
        }
    ];

    const runDemo = async () => {
        setIsRunning(true);
        setCompletedSteps([]);
        setBb84Key('');
        setKyberKey('');
        setHybridKey('');
        setEncryptedMessage('');
        setDecryptedMessage('');

        for (let i = 0; i < steps.length; i++) {
            setCurrentStep(i);
            await new Promise(resolve => setTimeout(resolve, 2000));
            steps[i].action();
            setCompletedSteps(prev => [...prev, i]);
            await new Promise(resolve => setTimeout(resolve, 500));
        }

        setIsRunning(false);
    };

    const reset = () => {
        setCurrentStep(0);
        setCompletedSteps([]);
        setBb84Key('');
        setKyberKey('');
        setHybridKey('');
        setEncryptedMessage('');
        setDecryptedMessage('');
        setIsRunning(false);
    };

    return (
        <div className="mt-6">
            <div className="flex justify-end mb-6 space-x-3">
                <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={reset}
                    disabled={isRunning}
                    className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg font-semibold hover:bg-gray-300 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                >
                    <RotateCcw className="w-4 h-4" />
                    <span>Reset</span>
                </motion.button>
                <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={runDemo}
                    disabled={isRunning || !message.trim()}
                    className="px-6 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg font-semibold shadow-lg hover:shadow-xl transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                >
                    <Play className="w-4 h-4" />
                    <span>{isRunning ? 'Running...' : 'Start Demo'}</span>
                </motion.button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left Panel - Input */}
                <div className="lg:col-span-1 space-y-6">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="bg-white rounded-2xl shadow-xl p-6 border border-gray-200"
                    >
                        <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                            <Cpu className="w-5 h-5 mr-2 text-purple-600" />
                            Input Message
                        </h2>
                        <textarea
                            className="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent resize-none"
                            rows="4"
                            value={message}
                            onChange={(e) => setMessage(e.target.value)}
                            placeholder="Enter your message..."
                            disabled={isRunning}
                        />
                        <p className="text-xs text-gray-500 mt-2">This message will be encrypted using quantum-resistant cryptography</p>
                    </motion.div>

                    {/* Generated Keys */}
                    <AnimatePresence>
                        {bb84Key && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                className="bg-gradient-to-br from-purple-900 to-pink-900 rounded-2xl shadow-xl p-6 text-white"
                            >
                                <h3 className="text-sm font-semibold mb-2 flex items-center">
                                    <Radio className="w-4 h-4 mr-2" />
                                    BB84 Quantum Key
                                </h3>
                                <div className="bg-black/30 rounded-lg p-3 font-mono text-xs break-all">
                                    {bb84Key}
                                </div>
                            </motion.div>
                        )}

                        {kyberKey && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                className="bg-gradient-to-br from-blue-900 to-cyan-900 rounded-2xl shadow-xl p-6 text-white"
                            >
                                <h3 className="text-sm font-semibold mb-2 flex items-center">
                                    <Shield className="w-4 h-4 mr-2" />
                                    Kyber PQC Key
                                </h3>
                                <div className="bg-black/30 rounded-lg p-3 font-mono text-xs break-all">
                                    {kyberKey}
                                </div>
                            </motion.div>
                        )}

                        {hybridKey && (
                            <motion.div
                                initial={{ opacity: 0, scale: 0.8 }}
                                animate={{ opacity: 1, scale: 1 }}
                                exit={{ opacity: 0, scale: 0.8 }}
                                transition={{ type: "spring", stiffness: 200, damping: 20 }}
                                className="relative bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-900 rounded-2xl shadow-2xl p-6 text-white overflow-hidden"
                            >
                                {/* Animated background particles */}
                                <motion.div
                                    animate={{
                                        backgroundPosition: ['0% 0%', '100% 100%'],
                                    }}
                                    transition={{ duration: 3, repeat: Infinity, repeatType: "reverse" }}
                                    className="absolute inset-0 opacity-20"
                                    style={{
                                        backgroundImage: 'radial-gradient(circle, white 1px, transparent 1px)',
                                        backgroundSize: '20px 20px'
                                    }}
                                />

                                <div className="relative">
                                    <h3 className="text-sm font-semibold mb-2 flex items-center">
                                        <motion.div
                                            animate={{ rotate: 360 }}
                                            transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                                        >
                                            <Key className="w-4 h-4 mr-2" />
                                        </motion.div>
                                        Hybrid Master Key (KDF)
                                    </h3>
                                    <div className="bg-black/40 rounded-lg p-3 font-mono text-xs break-all border border-white/20 shadow-inner">
                                        {hybridKey}
                                    </div>
                                    <div className="mt-3 flex items-center text-xs text-purple-200">
                                        <Zap className="w-3 h-3 mr-1" />
                                        <span>Quantum + Post-Quantum Security</span>
                                    </div>
                                </div>
                            </motion.div>
                        )}

                        {encryptedMessage && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                className="bg-gradient-to-br from-green-900 to-emerald-900 rounded-2xl shadow-xl p-6 text-white"
                            >
                                <h3 className="text-sm font-semibold mb-2 flex items-center">
                                    <Lock className="w-4 h-4 mr-2" />
                                    Encrypted Message
                                </h3>
                                <div className="bg-black/30 rounded-lg p-3 font-mono text-xs break-all">
                                    {encryptedMessage}
                                </div>
                            </motion.div>
                        )}

                        {decryptedMessage && (
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                className="bg-gradient-to-br from-green-600 to-emerald-600 rounded-2xl shadow-xl p-6 text-white"
                            >
                                <h3 className="text-sm font-semibold mb-2 flex items-center">
                                    <CheckCircle className="w-4 h-4 mr-2" />
                                    Decrypted Message
                                </h3>
                                <div className="bg-white/20 rounded-lg p-3 text-base">
                                    {decryptedMessage}
                                </div>
                                <p className="text-xs text-green-100 mt-2">✓ Message successfully decrypted and verified</p>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                {/* Right Panel - Process Steps */}
                <div className="lg:col-span-2 space-y-4">
                    <h2 className="text-2xl font-bold text-gray-900 mb-4">Encryption Process</h2>
                    {steps.map((step, index) => {
                        const StepIcon = step.icon;
                        const isActive = index === currentStep && isRunning;
                        const isCompleted = completedSteps.includes(index);
                        const isPending = !isCompleted && !isActive;

                        return (
                            <motion.div
                                key={step.id}
                                initial={{ opacity: 0, x: 50 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: index * 0.1 }}
                                className={`relative bg-white rounded-xl shadow-lg p-6 border-2 transition-all ${isActive
                                    ? 'border-purple-500 shadow-purple-200 scale-105'
                                    : isCompleted
                                        ? 'border-green-500'
                                        : 'border-gray-200'
                                    }`}
                            >
                                <div className="flex items-start space-x-4">
                                    {/* Step Number & Icon */}
                                    <div className="flex-shrink-0">
                                        <div className={`w-14 h-14 rounded-full bg-gradient-to-r ${step.color} flex items-center justify-center ${isActive ? 'animate-pulse' : ''} shadow-lg`}>
                                            <StepIcon className="w-7 h-7 text-white" />
                                        </div>
                                        <div className="text-center mt-2 text-xs font-bold text-gray-500">
                                            Step {index + 1}
                                        </div>
                                    </div>

                                    {/* Content */}
                                    <div className="flex-1">
                                        <div className="flex items-center justify-between mb-2">
                                            <h3 className="font-bold text-gray-900 text-lg">{step.title}</h3>
                                            {isCompleted && (
                                                <motion.div
                                                    initial={{ scale: 0 }}
                                                    animate={{ scale: 1 }}
                                                    className="flex items-center text-green-600 font-medium text-sm"
                                                >
                                                    <CheckCircle className="w-5 h-5 mr-1" />
                                                    Complete
                                                </motion.div>
                                            )}
                                            {isActive && (
                                                <motion.div
                                                    animate={{ opacity: [0.5, 1, 0.5] }}
                                                    transition={{ duration: 1.5, repeat: Infinity }}
                                                    className="flex items-center text-purple-600 font-medium text-sm"
                                                >
                                                    <Zap className="w-5 h-5 mr-1" />
                                                    Processing...
                                                </motion.div>
                                            )}
                                        </div>
                                        <p className="text-sm text-purple-600 font-medium mb-2">{step.subtitle}</p>
                                        <p className="text-sm text-gray-600 leading-relaxed">{step.description}</p>

                                        {/* Progress Bar for Active Step */}
                                        {isActive && (
                                            <motion.div
                                                initial={{ width: 0 }}
                                                animate={{ width: '100%' }}
                                                transition={{ duration: 2 }}
                                                className="mt-4 h-2 bg-gradient-to-r from-purple-500 to-blue-500 rounded-full"
                                            />
                                        )}
                                    </div>

                                    {/* Arrow to next step */}
                                    {index < steps.length - 1 && (
                                        <div className="absolute -bottom-6 left-1/2 transform -translate-x-1/2 z-10">
                                            <ChevronRight className={`w-6 h-6 rotate-90 ${isCompleted ? 'text-green-500' : 'text-gray-300'}`} />
                                        </div>
                                    )}
                                </div>
                            </motion.div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

const LiveSimulationDemo = () => {
    const [aliceMessage, setAliceMessage] = useState('');
    const [bobMessage, setBobMessage] = useState('');
    const [inspectorData, setInspectorData] = useState(null);

    const handleSend = () => {
        if (!aliceMessage.trim()) return;

        // Simulate Encryption
        const nonce = Array.from({ length: 12 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
        const ciphertext = btoa(aliceMessage).split('').map(c => c.charCodeAt(0).toString(16)).join('');
        const tag = "a1b2c3d4e5f67890";
        const aad = "alice:bob:timestamp";

        setInspectorData({
            plaintext: aliceMessage,
            nonce,
            ciphertext,
            tag,
            aad
        });

        // Simulate Decryption delay
        setTimeout(() => {
            setBobMessage(aliceMessage);
        }, 1500);
    };

    return (
        <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
            {/* Alice Panel */}
            <div className="bg-white rounded-xl shadow-lg border border-gray-200 flex flex-col">
                <div className="p-4 border-b border-gray-100 bg-purple-50 rounded-t-xl">
                    <h3 className="font-bold text-gray-900 flex items-center">
                        <div className="w-8 h-8 rounded-full bg-purple-600 text-white flex items-center justify-center mr-2">A</div>
                        Alice (Sender)
                    </h3>
                </div>
                <div className="p-6 flex-1 flex flex-col">
                    <textarea
                        className="w-full flex-1 p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 resize-none mb-4"
                        placeholder="Type a message to encrypt..."
                        value={aliceMessage}
                        onChange={(e) => setAliceMessage(e.target.value)}
                    />
                    <button
                        onClick={handleSend}
                        disabled={!aliceMessage}
                        className="w-full py-3 bg-purple-600 text-white rounded-lg font-semibold hover:bg-purple-700 transition disabled:opacity-50"
                    >
                        Encrypt & Send
                    </button>
                </div>
            </div>

            {/* Inspector Panel */}
            <div className="bg-gray-900 rounded-xl shadow-lg border border-gray-800 flex flex-col overflow-hidden">
                <div className="p-4 border-b border-gray-800 bg-gray-950">
                    <h3 className="font-bold text-green-400 flex items-center font-mono">
                        <Terminal className="w-5 h-5 mr-2" />
                        Network Inspector
                    </h3>
                </div>
                <div className="p-6 flex-1 font-mono text-xs text-green-300 overflow-y-auto space-y-4">
                    {!inspectorData ? (
                        <div className="text-gray-500 italic text-center mt-20">Waiting for transmission...</div>
                    ) : (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="space-y-4"
                        >
                            <div>
                                <span className="text-gray-500"># Intercepted Packet</span>
                            </div>
                            <div>
                                <span className="text-blue-400">Nonce (12 bytes):</span>
                                <div className="break-all text-white">{inspectorData.nonce}</div>
                            </div>
                            <div>
                                <span className="text-blue-400">AAD:</span>
                                <div className="break-all text-white">{inspectorData.aad}</div>
                            </div>
                            <div>
                                <span className="text-red-400">Ciphertext (AES-256-GCM):</span>
                                <div className="break-all text-white opacity-80">{inspectorData.ciphertext}</div>
                            </div>
                            <div>
                                <span className="text-yellow-400">Auth Tag (16 bytes):</span>
                                <div className="break-all text-white">{inspectorData.tag}</div>
                            </div>
                            <div className="pt-4 border-t border-gray-800">
                                <span className="text-gray-500"># Status: </span>
                                <span className="text-green-500">ENCRYPTED</span>
                            </div>
                        </motion.div>
                    )}
                </div>
            </div>

            {/* Bob Panel */}
            <div className="bg-white rounded-xl shadow-lg border border-gray-200 flex flex-col">
                <div className="p-4 border-b border-gray-100 bg-blue-50 rounded-t-xl">
                    <h3 className="font-bold text-gray-900 flex items-center">
                        <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center mr-2">B</div>
                        Bob (Recipient)
                    </h3>
                </div>
                <div className="p-6 flex-1 bg-gray-50 flex flex-col justify-center items-center text-center">
                    {bobMessage ? (
                        <motion.div
                            initial={{ scale: 0.8, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 w-full"
                        >
                            <div className="text-xs text-gray-400 mb-2">Decrypted Message</div>
                            <div className="text-lg font-medium text-gray-900">{bobMessage}</div>
                            <div className="mt-4 flex items-center justify-center text-green-600 text-sm">
                                <CheckCircle className="w-4 h-4 mr-1" />
                                Verified Source
                            </div>
                        </motion.div>
                    ) : (
                        <div className="text-gray-400">
                            <Lock className="w-12 h-12 mx-auto mb-2 opacity-20" />
                            <p>Waiting for encrypted message...</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Demo;
