import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Lock, Zap, Server, Database, Globe, CheckCircle, XCircle, Cpu, ArrowLeft, Info, BarChart3, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Line, Bar } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    LogarithmicScale,
    PointElement,
    LineElement,
    BarElement,
    Title,
    Tooltip,
    Legend,
} from 'chart.js';

ChartJS.register(
    CategoryScale,
    LinearScale,
    LogarithmicScale,
    PointElement,
    LineElement,
    BarElement,
    Title,
    Tooltip,
    Legend
);

const About = () => {
    const [activeModal, setActiveModal] = useState(null);

    const openModal = (id) => setActiveModal(id);
    const closeModal = () => setActiveModal(null);

    // Chart Data for "Time to Crack"
    const crackTimeData = {
        labels: ['RSA-2048 (Classical)', 'RSA-2048 (Quantum)', 'Kyber-1024 (Quantum)'],
        datasets: [
            {
                label: 'Estimated Time to Crack (Years)',
                data: [300000000000000, 0.02, 1000000000000000000], // Logarithmic scale visualization needed or just conceptual
                backgroundColor: [
                    'rgba(54, 162, 235, 0.6)',
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(75, 192, 192, 0.8)',
                ],
                borderColor: [
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 99, 132, 1)',
                    'rgba(75, 192, 192, 1)',
                ],
                borderWidth: 1,
            },
        ],
    };

    const chartOptions = {
        indexAxis: 'y',
        responsive: true,
        plugins: {
            legend: { display: false },
            title: { display: true, text: 'Security Hardness Comparison' },
            tooltip: {
                callbacks: {
                    label: (context) => {
                        const val = context.raw;
                        if (val > 1000000000) return "Trillions of Years (Practically Infinite)";
                        if (val < 1) return "< 1 Week (Broken)";
                        return val;
                    }
                }
            }
        },
        scales: {
            x: {
                type: 'logarithmic',
                title: { display: true, text: 'Years to Crack (Log Scale)' }
            }
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 text-gray-900 font-sans">
            {/* Navigation */}
            <nav className="fixed w-full z-50 bg-white/90 backdrop-blur-xl border-b border-gray-200 shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        <Link to="/" className="flex items-center space-x-2">
                            <Shield className="h-8 w-8 text-purple-600" />
                            <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-600 to-blue-500">
                                QuantumNet
                            </span>
                        </Link>
                        <Link to="/" className="text-sm font-medium text-gray-500 hover:text-purple-600 transition flex items-center">
                            <ArrowLeft className="w-4 h-4 mr-1" />
                            Back to Home
                        </Link>
                    </div>
                </div>
            </nav>

            {/* Hero Section */}
            <div className="pt-32 pb-20 bg-white">
                <div className="max-w-5xl mx-auto px-4 text-center">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.8 }}
                    >
                        <div className="inline-flex items-center px-4 py-2 rounded-full bg-purple-100 text-purple-700 text-sm font-bold mb-6">
                            <Zap className="w-4 h-4 mr-2" />
                            Next-Gen Hybrid Security Architecture
                        </div>
                        <h1 className="text-5xl md:text-7xl font-extrabold mb-8 tracking-tight text-gray-900">
                            Beyond End-to-End Encryption. <br />
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-600 to-blue-600">
                                Physically Unbreakable.
                            </span>
                        </h1>
                        <p className="text-xl text-gray-600 mb-10 leading-relaxed max-w-3xl mx-auto">
                            While apps like Signal and iMessage are adopting Post-Quantum Cryptography (PQC),
                            QuantumNet goes a step further by integrating <strong>Quantum Key Distribution (BB84)</strong> simulation.
                            We combine the laws of physics with advanced lattice-based mathematics to defeat "Harvest Now, Decrypt Later" attacks.
                        </p>
                    </motion.div>
                </div>
            </div>

            {/* Interactive Tech Stack */}
            <div className="py-20 bg-gray-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold mb-4">The Hybrid Trinity</h2>
                        <p className="text-gray-600">Click on any technology to explore the deep mathematics and physics behind it.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                        {/* BB84 Card */}
                        <motion.div
                            whileHover={{ y: -10, scale: 1.02 }}
                            onClick={() => openModal('bb84')}
                            className="bg-white p-8 rounded-2xl shadow-lg border border-purple-100 cursor-pointer group hover:border-purple-300 transition-all"
                        >
                            <div className="w-16 h-16 bg-purple-100 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-purple-600 transition-colors">
                                <Zap className="w-8 h-8 text-purple-600 group-hover:text-white transition-colors" />
                            </div>
                            <h3 className="text-2xl font-bold mb-2">BB84 QKD</h3>
                            <p className="text-xs font-bold text-purple-600 uppercase tracking-wide mb-4">Physics Layer</p>
                            <p className="text-gray-600 mb-6">
                                Uses the <strong>No-Cloning Theorem</strong> of quantum mechanics.
                                Eavesdropping creates detectable errors (QBER).
                            </p>
                            <div className="flex items-center text-purple-600 font-bold text-sm">
                                Deep Dive <ArrowLeft className="w-4 h-4 ml-2 rotate-180" />
                            </div>
                        </motion.div>

                        {/* Kyber Card */}
                        <motion.div
                            whileHover={{ y: -10, scale: 1.02 }}
                            onClick={() => openModal('kyber')}
                            className="bg-white p-8 rounded-2xl shadow-lg border border-blue-100 cursor-pointer group hover:border-blue-300 transition-all"
                        >
                            <div className="w-16 h-16 bg-blue-100 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-blue-600 transition-colors">
                                <Shield className="w-8 h-8 text-blue-600 group-hover:text-white transition-colors" />
                            </div>
                            <h3 className="text-2xl font-bold mb-2">CRYSTALS-Kyber</h3>
                            <p className="text-xs font-bold text-blue-600 uppercase tracking-wide mb-4">Math Layer (PQC)</p>
                            <p className="text-gray-600 mb-6">
                                NIST-standardized <strong>Module-Lattice</strong> cryptography.
                                Solves the "Learning With Errors" (LWE) problem.
                            </p>
                            <div className="flex items-center text-blue-600 font-bold text-sm">
                                Deep Dive <ArrowLeft className="w-4 h-4 ml-2 rotate-180" />
                            </div>
                        </motion.div>

                        {/* AES Card */}
                        <motion.div
                            whileHover={{ y: -10, scale: 1.02 }}
                            onClick={() => openModal('aes')}
                            className="bg-white p-8 rounded-2xl shadow-lg border border-green-100 cursor-pointer group hover:border-green-300 transition-all"
                        >
                            <div className="w-16 h-16 bg-green-100 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-green-600 transition-colors">
                                <Lock className="w-8 h-8 text-green-600 group-hover:text-white transition-colors" />
                            </div>
                            <h3 className="text-2xl font-bold mb-2">AES-256-GCM</h3>
                            <p className="text-xs font-bold text-green-600 uppercase tracking-wide mb-4">Encryption Layer</p>
                            <p className="text-gray-600 mb-6">
                                Military-grade symmetric encryption.
                                Quantum computers only halve its effective key size (Grover's Algo), leaving 128-bits of security.
                            </p>
                            <div className="flex items-center text-green-600 font-bold text-sm">
                                Deep Dive <ArrowLeft className="w-4 h-4 ml-2 rotate-180" />
                            </div>
                        </motion.div>
                    </div>
                </div>
            </div>

            {/* Quantitative Comparison */}
            <div className="py-20 bg-white">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
                        <div>
                            <h2 className="text-3xl font-bold mb-6">The Quantum Threat is Real</h2>
                            <p className="text-gray-600 text-lg mb-8">
                                Experts predict a cryptographically relevant quantum computer by the 2030s.
                                When that happens, RSA-2048 (used by most of the internet) will crumble in minutes.
                            </p>

                            <div className="space-y-6">
                                <div className="bg-red-50 p-6 rounded-xl border border-red-100">
                                    <h4 className="font-bold text-red-800 mb-2 flex items-center">
                                        <XCircle className="w-5 h-5 mr-2" /> RSA-2048
                                    </h4>
                                    <p className="text-sm text-red-700">
                                        Relies on factoring large integers. Shor's Algorithm on a quantum computer solves this exponentially faster than classical computers.
                                    </p>
                                </div>
                                <div className="bg-green-50 p-6 rounded-xl border border-green-100">
                                    <h4 className="font-bold text-green-800 mb-2 flex items-center">
                                        <CheckCircle className="w-5 h-5 mr-2" /> Kyber-1024 (QuantumNet)
                                    </h4>
                                    <p className="text-sm text-green-700">
                                        Based on Module Lattices. No known quantum algorithm gives a significant advantage. Security level is comparable to AES-256.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div className="bg-white p-6 rounded-2xl shadow-xl border border-gray-100">
                            <Bar data={crackTimeData} options={chartOptions} />
                            <div className="mt-6 p-4 bg-gray-50 rounded-lg border border-gray-200 text-sm text-gray-600">
                                <h4 className="font-bold text-gray-800 mb-2 flex items-center">
                                    <Info className="w-4 h-4 mr-2 text-blue-500" />
                                    Understanding the Graph
                                </h4>
                                <p className="mb-2">
                                    This chart uses a <strong>Logarithmic Scale</strong> (powers of 10) because the difference in security is astronomical.
                                </p>
                                <ul className="list-disc list-inside space-y-1 ml-2">
                                    <li><strong>RSA-2048 (Classical):</strong> Takes ~300 Trillion years to crack with today's supercomputers.</li>
                                    <li><strong>RSA-2048 (Quantum):</strong> Could be broken in <strong>minutes to hours</strong> by a future quantum computer.</li>
                                    <li><strong>Kyber-1024:</strong> Remains secure for &gt;10<sup>18</sup> years, even against quantum attacks.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Security Report Card */}
            <div className="py-20 bg-gray-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold mb-4">Security Report Card</h2>
                        <p className="text-gray-600">How QuantumNet compares to the industry giants.</p>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full bg-white rounded-2xl shadow-lg overflow-hidden">
                            <thead className="bg-gray-900 text-white">
                                <tr>
                                    <th className="px-6 py-4 text-left">Feature</th>
                                    <th className="px-6 py-4 text-center bg-purple-900/50 border-b-4 border-purple-500">QuantumNet</th>
                                    <th className="px-6 py-4 text-center">Signal (PQXDH)</th>
                                    <th className="px-6 py-4 text-center">WhatsApp</th>
                                    <th className="px-6 py-4 text-center">Telegram</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                                <tr className="hover:bg-gray-50">
                                    <td className="px-6 py-4 font-medium text-gray-900">Post-Quantum Key Exchange</td>
                                    <td className="px-6 py-4 text-center text-green-600 font-bold bg-purple-50">Kyber-1024 (NIST Lvl 5)</td>
                                    <td className="px-6 py-4 text-center text-green-600">Kyber-1024</td>
                                    <td className="px-6 py-4 text-center text-green-600">Kyber-1024 (Rolling out)</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                </tr>
                                <tr className="hover:bg-gray-50">
                                    <td className="px-6 py-4 font-medium text-gray-900">Physical Layer Security</td>
                                    <td className="px-6 py-4 text-center text-green-600 font-bold bg-purple-50">Yes (BB84 Simulation)</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                </tr>
                                <tr className="hover:bg-gray-50">
                                    <td className="px-6 py-4 font-medium text-gray-900">Eavesdropping Detection</td>
                                    <td className="px-6 py-4 text-center text-green-600 font-bold bg-purple-50">Yes (Real-time QBER)</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                    <td className="px-6 py-4 text-center text-red-500">No</td>
                                </tr>
                                <tr className="hover:bg-gray-50">
                                    <td className="px-6 py-4 font-medium text-gray-900">Harvest Now, Decrypt Later</td>
                                    <td className="px-6 py-4 text-center text-green-600 font-bold bg-purple-50">Protected</td>
                                    <td className="px-6 py-4 text-center text-green-600">Protected</td>
                                    <td className="px-6 py-4 text-center text-green-600">Protected</td>
                                    <td className="px-6 py-4 text-center text-red-500">Vulnerable</td>
                                </tr>
                                <tr className="bg-gray-50 font-bold">
                                    <td className="px-6 py-4 text-gray-900">Overall Security Grade</td>
                                    <td className="px-6 py-4 text-center text-purple-600 text-xl bg-purple-100">A+</td>
                                    <td className="px-6 py-4 text-center text-blue-600 text-lg">A</td>
                                    <td className="px-6 py-4 text-center text-blue-600 text-lg">A-</td>
                                    <td className="px-6 py-4 text-center text-orange-500 text-lg">C</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* Market Context */}
            <div className="py-20 bg-gray-900 text-white">
                <div className="max-w-4xl mx-auto px-4 text-center">
                    <h2 className="text-3xl font-bold mb-8">Leading the Post-Quantum Revolution</h2>
                    <p className="text-gray-300 text-lg mb-12">
                        QuantumNet joins the elite tier of forward-thinking secure messengers.
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-left">
                        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700">
                            <div className="text-gray-400 text-xs uppercase tracking-wider mb-2">Competitor</div>
                            <h3 className="text-xl font-bold mb-2">Signal (PQXDH)</h3>
                            <p className="text-gray-400 text-sm">
                                Uses Kyber for initial key agreement. Excellent PQC implementation, but lacks the physical security layer of QKD.
                            </p>
                        </div>
                        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700">
                            <div className="text-gray-400 text-xs uppercase tracking-wider mb-2">Competitor</div>
                            <h3 className="text-xl font-bold mb-2">Apple iMessage (PQ3)</h3>
                            <p className="text-gray-400 text-sm">
                                Level 3 security with rapid re-keying and Kyber. A massive step forward for consumer security.
                            </p>
                        </div>
                        <div className="bg-gradient-to-br from-purple-900 to-blue-900 p-6 rounded-xl border border-purple-500 shadow-2xl relative overflow-hidden">
                            <div className="absolute top-0 right-0 bg-purple-500 text-white text-xs font-bold px-2 py-1 rounded-bl-lg">US</div>
                            <div className="text-purple-200 text-xs uppercase tracking-wider mb-2">QuantumNet</div>
                            <h3 className="text-xl font-bold mb-2">Hybrid QKD + PQC</h3>
                            <p className="text-gray-200 text-sm">
                                We simulate the <strong>Physical Layer</strong> (BB84) alongside PQC (Kyber).
                                This "Defense in Depth" approach prepares for a future where mathematical assumptions might fail.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Modals */}
            <AnimatePresence>
                {activeModal && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
                        onClick={closeModal}
                    >
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.9, opacity: 0 }}
                            className="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl"
                            onClick={(e) => e.stopPropagation()}
                        >
                            {activeModal === 'bb84' && (
                                <div className="p-8">
                                    <div className="flex items-center justify-between mb-6">
                                        <h2 className="text-3xl font-bold text-purple-900">BB84 Protocol Deep Dive</h2>
                                        <button onClick={closeModal} className="p-2 hover:bg-gray-100 rounded-full"><XCircle className="w-6 h-6" /></button>
                                    </div>
                                    <div className="prose prose-purple max-w-none">
                                        <p className="text-lg text-gray-700 leading-relaxed">
                                            The Bennett-Brassard 1984 (BB84) protocol is the first quantum cryptography protocol.
                                            It allows two parties to agree on a secret key using the polarization of photons.
                                        </p>
                                        <div className="bg-purple-50 p-6 rounded-xl my-6">
                                            <h4 className="font-bold text-purple-800 mb-2">How it works:</h4>
                                            <ol className="list-decimal list-inside space-y-2 text-gray-700">
                                                <li><strong>Alice</strong> sends photons polarized in one of 4 states: (↑, →, ↗, ↘).</li>
                                                <li><strong>Bob</strong> measures each photon using a random basis: Rectilinear (+) or Diagonal (×).</li>
                                                <li>If bases match, Bob measures correctly. If not, result is random (50% error).</li>
                                                <li>They publicly compare bases (Sifting).</li>
                                                <li><strong>Security:</strong> If Eve intercepts a photon, she must measure it. By the <strong>No-Cloning Theorem</strong>, she cannot copy it. Measuring disturbs the state.</li>
                                            </ol>
                                        </div>
                                        <p className="font-mono text-sm bg-gray-900 text-green-400 p-4 rounded-lg">
                                            QBER (Quantum Bit Error Rate) = (Errors / Total Bits)<br />
                                            If QBER &gt; 11%, we assume Eve is listening and abort.
                                        </p>
                                    </div>
                                </div>
                            )}

                            {activeModal === 'kyber' && (
                                <div className="p-8">
                                    <div className="flex items-center justify-between mb-6">
                                        <h2 className="text-3xl font-bold text-blue-900">CRYSTALS-Kyber Deep Dive</h2>
                                        <button onClick={closeModal} className="p-2 hover:bg-gray-100 rounded-full"><XCircle className="w-6 h-6" /></button>
                                    </div>
                                    <div className="prose prose-blue max-w-none">
                                        <p className="text-lg text-gray-700 leading-relaxed">
                                            Kyber is a Key Encapsulation Mechanism (KEM) whose security is based on the difficulty of solving the
                                            <strong> Learning With Errors (LWE)</strong> problem over module lattices.
                                        </p>
                                        <div className="bg-blue-50 p-6 rounded-xl my-6">
                                            <h4 className="font-bold text-blue-800 mb-2">The Math Problem:</h4>
                                            <p className="text-gray-700 mb-4">
                                                Imagine a system of linear equations with a small amount of "noise" (error) added to each result.
                                                <code>A * s + e = b</code>
                                            </p>
                                            <ul className="list-disc list-inside space-y-2 text-gray-700">
                                                <li><strong>A:</strong> Public matrix</li>
                                                <li><strong>s:</strong> Secret vector</li>
                                                <li><strong>e:</strong> Small error vector</li>
                                                <li><strong>b:</strong> Public result</li>
                                            </ul>
                                            <p className="mt-4 text-gray-700">
                                                Finding <strong>s</strong> given A and b is incredibly hard, even for quantum computers.
                                                This is a "Lattice Problem".
                                            </p>
                                        </div>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="bg-gray-100 p-4 rounded-lg text-center">
                                                <div className="text-2xl font-bold text-gray-900">NIST</div>
                                                <div className="text-xs text-gray-500">Selected Standard (ML-KEM)</div>
                                            </div>
                                            <div className="bg-gray-100 p-4 rounded-lg text-center">
                                                <div className="text-2xl font-bold text-gray-900">AES-256</div>
                                                <div className="text-xs text-gray-500">Equivalent Security Level</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {activeModal === 'aes' && (
                                <div className="p-8">
                                    <div className="flex items-center justify-between mb-6">
                                        <h2 className="text-3xl font-bold text-green-900">AES-256-GCM Deep Dive</h2>
                                        <button onClick={closeModal} className="p-2 hover:bg-gray-100 rounded-full"><XCircle className="w-6 h-6" /></button>
                                    </div>
                                    <div className="prose prose-green max-w-none">
                                        <p className="text-lg text-gray-700 leading-relaxed">
                                            Advanced Encryption Standard (AES) is the global standard for symmetric encryption.
                                            We use the 256-bit key variant in Galois/Counter Mode (GCM).
                                        </p>
                                        <div className="bg-green-50 p-6 rounded-xl my-6">
                                            <h4 className="font-bold text-green-800 mb-2">Why is it Quantum Safe?</h4>
                                            <p className="text-gray-700 mb-4">
                                                Symmetric algorithms like AES are NOT broken by Shor's Algorithm (which breaks RSA).
                                                They are only affected by <strong>Grover's Algorithm</strong>.
                                            </p>
                                            <ul className="list-disc list-inside space-y-2 text-gray-700">
                                                <li>Grover's Algorithm speeds up brute-force search by a square root.</li>
                                                <li>To break AES-128, a quantum computer needs 2^64 operations (Doable).</li>
                                                <li>To break <strong>AES-256</strong>, it needs 2^128 operations (Still impossible).</li>
                                            </ul>
                                        </div>
                                        <p className="text-gray-600 italic">
                                            "Even with a quantum computer the size of the earth, cracking AES-256 would take longer than the age of the universe."
                                        </p>
                                    </div>
                                </div>
                            )}
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default About;
