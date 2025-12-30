import React, { createContext, useState, useContext, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Check if user is logged in
        const token = localStorage.getItem('token');
        const username = localStorage.getItem('username');
        const userId = localStorage.getItem('user_id');
        const fullName = localStorage.getItem('full_name');
        const email = localStorage.getItem('email');
        const profilePicture = localStorage.getItem('profile_picture');

        if (token && username) {
            setUser({
                username,
                id: userId,
                full_name: fullName,
                email,
                profile_picture: profilePicture
            });
        }
        setLoading(false);
    }, []);

    const login = async (username, password) => {
        const params = new URLSearchParams();
        params.append('username', username);
        params.append('password', password);

        try {
            const response = await api.post('/auth/token', params, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            const { access_token, user_id, full_name, email, profile_picture } = response.data;

            localStorage.setItem('token', access_token);
            localStorage.setItem('username', response.data.username);
            localStorage.setItem('user_id', user_id);
            localStorage.setItem('full_name', full_name || '');
            localStorage.setItem('email', email || '');
            localStorage.setItem('profile_picture', profile_picture || '');

            setUser({
                username: response.data.username,
                id: user_id,
                full_name,
                email,
                profile_picture
            });
            return { success: true };
        } catch (error) {
            console.error("Login failed", error);
            let errorMessage = "Login failed";
            if (error.response?.data?.detail) {
                if (typeof error.response.data.detail === 'string') {
                    errorMessage = error.response.data.detail;
                } else {
                    errorMessage = JSON.stringify(error.response.data.detail);
                }
            }
            return { success: false, error: errorMessage };
        }
    };

    const register = async (username, email, password, fullName) => {
        const params = new URLSearchParams();
        params.append('username', username);
        params.append('email', email);
        params.append('password', password);
        if (fullName) params.append('full_name', fullName);

        try {
            await api.post('/auth/register', params, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            return { success: true };
        } catch (error) {
            console.error("Registration failed", error);
            let errorMessage = "Registration failed";
            if (error.response?.data?.detail) {
                if (typeof error.response.data.detail === 'string') {
                    errorMessage = error.response.data.detail;
                } else {
                    errorMessage = JSON.stringify(error.response.data.detail);
                }
            }
            return { success: false, error: errorMessage };
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('user_id');
        localStorage.removeItem('full_name');
        localStorage.removeItem('email');
        localStorage.removeItem('profile_picture');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, login, register, logout, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
