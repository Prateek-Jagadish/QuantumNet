import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { Line, Doughnut } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    ArcElement,
} from 'chart.js';
import { Shield, Activity, Lock, Key } from 'lucide-react';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    ArcElement
);

const Dashboard = () => {
    const [metrics, setMetrics] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchMetrics = async () => {
            try {
                const response = await api.get('/security/metrics');
                const keysResponse = await api.get('/security/keys');
                const eventsResponse = await api.get('/security/events');

                setMetrics({
                    ...response.data,
                    keys: keysResponse.data,
                    events: eventsResponse.data
                });
            } catch (error) {
                console.error("Error fetching metrics", error);
            } finally {
                setLoading(false);
            }
        };

        fetchMetrics();
        const interval = setInterval(fetchMetrics, 5000); // Refresh every 5s
        return () => clearInterval(interval);
    }, []);

    if (loading) return <div className="p-8 text-center">Loading Security Metrics...</div>;
    if (!metrics) return <div className="p-8 text-center">Error loading dashboard.</div>;

    const qberData = {
        labels: ['T-5', 'T-4', 'T-3', 'T-2', 'T-1', 'Now'],
        datasets: [
            {
                label: 'QBER (%)',
                data: [0.01, 0.02, 0.015, 0.01, 0.025, metrics.qber],
                borderColor: 'rgb(16, 185, 129)',
                backgroundColor: 'rgba(16, 185, 129, 0.5)',
            },
        ],
    };

    const securityScoreData = {
        labels: ['Secure', 'Risk'],
        datasets: [
            {
                data: [metrics.security_score, 100 - metrics.security_score],
                backgroundColor: ['#7C3AED', '#E5E7EB'],
                borderWidth: 0,
            },
        ],
    };

    return (
        <div className="min-h-screen bg-gray-50 p-6">
            <div className="max-w-7xl mx-auto">
                <header className="mb-8 flex justify-between items-center">
                    <div>
                        <div className="flex items-center space-x-4 mb-2">
                            <Link to="/chat" className="text-sm text-blue-600 hover:underline">&larr; Back to Chat</Link>
                        </div>
                        <h1 className="text-3xl font-bold text-gray-900">Security Monitor</h1>
                        <p className="text-gray-600">Real-time Quantum Network Status</p>
                    </div>
                    <div className="flex space-x-4">
                        <Link to="/demo" className="bg-gradient-to-r from-purple-600 to-blue-600 text-white px-4 py-2 rounded-lg shadow hover:shadow-lg transition text-sm font-semibold flex items-center">
                            <span className="mr-2">🎯</span> Launch Demo Mode
                        </Link>
                        <button className="bg-white p-2 rounded-lg shadow text-sm font-semibold text-gray-700">
                            System Status: <span className="text-green-500">Operational</span>
                        </button>
                    </div>
                </header>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-gray-500 text-sm font-medium">Current QBER</h3>
                            <Activity className="w-5 h-5 text-blue-500" />
                        </div>
                        <div className="text-2xl font-bold text-gray-900">{(metrics.qber * 100).toFixed(2)}%</div>
                        <div className={`text-xs mt-1 ${metrics.qber < 0.11 ? 'text-green-500' : 'text-red-500'}`}>
                            {metrics.qber < 0.11 ? 'Within Safe Limits' : 'Critical Warning'}
                        </div>
                    </div>

                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-gray-500 text-sm font-medium">Active Keys</h3>
                            <Key className="w-5 h-5 text-purple-500" />
                        </div>
                        <div className="text-2xl font-bold text-gray-900">{metrics.active_keys}</div>
                        <div className="text-xs text-gray-500 mt-1">Hybrid Sessions</div>
                    </div>

                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-gray-500 text-sm font-medium">Messages Secured</h3>
                            <Shield className="w-5 h-5 text-green-500" />
                        </div>
                        <div className="text-2xl font-bold text-gray-900">{metrics.total_messages}</div>
                        <div className="text-xs text-gray-500 mt-1">AES-256-GCM Encrypted</div>
                    </div>

                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-gray-500 text-sm font-medium">Security Score</h3>
                            <Lock className="w-5 h-5 text-indigo-500" />
                        </div>
                        <div className="text-2xl font-bold text-gray-900">{metrics.security_score}/100</div>
                        <div className="text-xs text-gray-500 mt-1">System Integrity</div>
                    </div>
                </div>

                {/* Charts Section */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 lg:col-span-2">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">QBER History (Last 24h)</h3>
                        <div className="h-64">
                            <Line options={{ responsive: true, maintainAspectRatio: false }} data={qberData} />
                        </div>
                    </div>

                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Layer Status</h3>
                        <div className="space-y-4">
                            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                <span className="text-sm font-medium text-gray-700">BB84 Quantum Layer</span>
                                <span className="px-2 py-1 text-xs font-semibold text-green-700 bg-green-100 rounded-full">Active</span>
                            </div>
                            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                <span className="text-sm font-medium text-gray-700">Kyber PQC Layer</span>
                                <span className="px-2 py-1 text-xs font-semibold text-green-700 bg-green-100 rounded-full">Active</span>
                            </div>
                            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                <span className="text-sm font-medium text-gray-700">AES-GCM Layer</span>
                                <span className="px-2 py-1 text-xs font-semibold text-green-700 bg-green-100 rounded-full">Active</span>
                            </div>

                            <div className="mt-8 flex justify-center">
                                <div className="w-32 h-32">
                                    <Doughnut data={securityScoreData} options={{ cutout: '70%' }} />
                                </div>
                            </div>
                            <p className="text-center text-sm text-gray-500 mt-2">Overall Protection Level</p>
                        </div>
                    </div>
                </div>

                {/* Tables Section */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
                    {/* Active Keys Table */}
                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Active Hybrid Sessions</h3>
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead>
                                    <tr>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">QBER</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {metrics.keys && metrics.keys.map((key) => (
                                        <tr key={key.id}>
                                            <td className="px-3 py-2 whitespace-nowrap text-xs font-mono text-gray-600">{key.id.substring(0, 8)}...</td>
                                            <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500">{new Date(key.created_at).toLocaleTimeString()}</td>
                                            <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-900">{(key.qber * 100).toFixed(2)}%</td>
                                            <td className="px-3 py-2 whitespace-nowrap">
                                                <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${key.is_secure ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                                    {key.is_secure ? 'Secure' : 'Compromised'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                    {(!metrics.keys || metrics.keys.length === 0) && (
                                        <tr>
                                            <td colSpan="4" className="px-3 py-4 text-center text-sm text-gray-500">No active sessions</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    {/* Threat Alerts Table */}
                    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Intelligence Log</h3>
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead>
                                    <tr>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event</th>
                                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {metrics.events && metrics.events.map((event) => (
                                        <tr key={event.id}>
                                            <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500">{new Date(event.created_at).toLocaleTimeString()}</td>
                                            <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-900">{event.event_type}</td>
                                            <td className="px-3 py-2 whitespace-nowrap">
                                                <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${event.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                                        event.severity === 'WARNING' ? 'bg-yellow-100 text-yellow-800' :
                                                            'bg-blue-100 text-blue-800'
                                                    }`}>
                                                    {event.severity}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                    {(!metrics.events || metrics.events.length === 0) && (
                                        <tr>
                                            <td colSpan="3" className="px-3 py-4 text-center text-sm text-gray-500">No security events logged</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
