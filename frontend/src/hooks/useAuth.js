import React, { createContext, useContext, useState, useCallback } from 'react';
import { API_BASE } from '../config.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('moonkeep_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState(() => {
    return localStorage.getItem('moonkeep_token') || null;
  });

  const isAuthenticated = !!token;

  const login = useCallback(async (username, password) => {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(err.detail || 'Invalid credentials');
    }
    const data = await res.json();
    localStorage.setItem('moonkeep_token', data.token);
    localStorage.setItem('moonkeep_user', JSON.stringify({ username: data.username, role: data.role }));
    setToken(data.token);
    setUser({ username: data.username, role: data.role });
    return data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('moonkeep_token');
    localStorage.removeItem('moonkeep_user');
    setToken(null);
    setUser(null);
  }, []);

  const authFetch = useCallback(async (url, options = {}) => {
    const headers = { ...options.headers };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      logout();
      throw new Error('Session expired');
    }
    return res;
  }, [token, logout]);

  const value = { user, token, login, logout, isAuthenticated, authFetch };

  return React.createElement(AuthContext.Provider, { value }, children);
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
