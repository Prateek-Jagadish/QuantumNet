import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Mail,
  MapPin,
  Phone,
  Send,
  Github,
  Linkedin,
  Twitter,
  ArrowLeft
} from 'lucide-react';
import { motion } from 'framer-motion';

const Contact = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    message: ''
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    alert("Thanks for reaching out! We'll get back to you shortly.");
    setFormData({ name: '', email: '', message: '' });
  };

  const team = [
    {
      id: 1,
      usn: "2BU22AD024",
      name: "Naveen Dodamani",
      role: "Full Stack Developer",
      bio: "Expert in real-time systems and WebSocket architecture. Built the core messaging engine.",
      image: "/assets/Naveen24.jpeg",
      social: {
        linkedin: "https://www.linkedin.com/in/naveen-dodamani-81ab9533b",
        github: "https://github.com/Naveen-D004"
      }
    },
    {
      id: 2,
      usn: "2BU22AD026",
      name: "Omkar Hiremath",
      role: "Security Engineer",
      bio: "Specialist in network security. Ensures the integrity and robustness of the BB84 simulation.",
      image: "/assets/om.png",
      social: {
        linkedin: "https://www.linkedin.com/in/omkar-hiremath-06a654376?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app",
        github: "https://github.com/Omkar-711"
      }
    },
    {
      id: 3,
      usn: "2BU22AD029",
      name: "Prateek Hiremath",
      role: "AI Engineer",
      bio: "Focused on designing and deploying intelligent systems, algorithm optimization, and AI-powered feature development.",
      image: "/assets/prateek.jpeg",
      social: {
        linkedin: "www.linkedin.com/in/prateekhiremath6754",
        github: "https://github.com/Prateek-Jagadish"
      }
    },
    {
      id: 4,
      usn: "2BU22AD036",
      name: "Rahul Kamati",
      role: "UI/UX Designer",
      bio: "Crafting intuitive interfaces for complex security tools. Designed the Live Encryption Demo.",
      image: "/assets/Rahul36.jpg",
      social: {
        linkedin: "https://www.linkedin.com/in/rahul-kamati-99a220286?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=ios_app",
        github: "https://github.com/rahul17-AI"
      }
    }
  ];

  return (
    <div className="min-h-screen bg-white text-gray-900 font-sans">

      {/* Navigation */}
      <nav className="fixed w-full z-50 bg-white/80 backdrop-blur-xl border-b border-gray-100">
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

      {/* Header */}
      <div className="pt-32 pb-12 bg-gradient-to-b from-blue-50 to-white text-center">
        <h1 className="text-4xl font-bold mb-4">Get in Touch</h1>
        <p className="text-xl text-gray-600 max-w-2xl mx-auto px-4">
          Have questions about our quantum security protocols? We'd love to hear from you.
        </p>
      </div>

      {/* Contact Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">

          {/* Contact Info */}
          <div className="space-y-8">
            <div className="bg-purple-50 p-8 rounded-2xl border border-purple-100">
              <h3 className="text-xl font-bold mb-6 text-purple-900">
                Contact Information
              </h3>

              <div className="space-y-4">
                <div className="flex items-start space-x-4">
                  <Mail className="w-6 h-6 text-purple-600 mt-1" />
                  <div>
                    <p className="font-medium text-gray-900">Email Us</p>
                    <p className="text-gray-600">contact@quantumnet.secure</p>
                  </div>
                </div>

                <div className="flex items-start space-x-4">
                  <MapPin className="w-6 h-6 text-purple-600 mt-1" />
                  <div>
                    <p className="font-medium text-gray-900">Research Lab</p>
                    <p className="text-gray-600">
                      123 Quantum Valley, Qubit City, QC 10101
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-4">
                  <Phone className="w-6 h-6 text-purple-600 mt-1" />
                  <div>
                    <p className="font-medium text-gray-900">Call Us</p>
                    <p className="text-gray-600">+1 (555) 123-4567</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Contact Form */}
          <div className="bg-white p-8 rounded-2xl shadow-lg border border-gray-100">
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
                <input
                  type="text"
                  required
                  className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-purple-500"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
                <input
                  type="email"
                  required
                  className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-purple-500"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Message</label>
                <textarea
                  required
                  rows="4"
                  className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-purple-500"
                  value={formData.message}
                  onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                />
              </div>

              <button
                type="submit"
                className="w-full py-3 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg font-bold flex items-center justify-center"
              >
                <Send className="w-5 h-5 mr-2" />
                Send Message
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* Meet the Squad */}
      <div className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">Meet the Squad</h2>
            <p className="text-gray-600">The minds behind the encryption.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {team.map((member) => (
              <motion.div
                key={member.id}
                whileHover={{ y: -10 }}
                className="bg-white rounded-2xl shadow-md overflow-hidden border border-gray-100"
              >
                <div className="h-48 overflow-hidden">
                  <img
                    src={member.image}
                    alt={member.name}
                    className="w-full h-full object-cover"
                  />
                </div>

                <div className="p-6">
                  <h3 className="text-xl font-bold text-gray-900">
                    {member.name}
                  </h3>

                  <p className="text-xs text-gray-500 mb-1">
                    USN: {member.usn}
                  </p>

                  <p className="text-purple-600 font-medium text-sm mb-3">
                    {member.role}
                  </p>

                  <p className="text-gray-600 text-sm mb-4">
                    {member.bio}
                  </p>

                  <div className="flex space-x-3">
                    {member.social.github && (
                      <a href={member.social.github}>
                        <Github className="w-5 h-5 text-gray-400 hover:text-gray-900" />
                      </a>
                    )}
                    {member.social.linkedin && (
                      <a href={member.social.linkedin}>
                        <Linkedin className="w-5 h-5 text-gray-400 hover:text-blue-700" />
                      </a>
                    )}
                    {member.social.twitter && (
                      <a href={member.social.twitter}>
                        <Twitter className="w-5 h-5 text-gray-400 hover:text-blue-400" />
                      </a>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Contact;
