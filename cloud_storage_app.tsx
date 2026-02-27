import React, { useState, useEffect } from 'react';
import { Cloud, Home, Clock, HardDrive, Users, Star, CloudOff, Archive, Trash2, Search, Grid, List, Plus, Upload, FolderPlus, Menu, X, Key, Crown, Shield, File, Folder, Mail, Lock, Eye, EyeOff, LogOut, MoreVertical, Download } from 'lucide-react';

const AlertTriangle = ({ className }) => (
  <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
);

const CloudStorageApp = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [showAuth, setShowAuth] = useState(true);
  const [authMode, setAuthMode] = useState('login');
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState('');
  const [showRecaptcha, setShowRecaptcha] = useState(false);
  const [recaptchaVerified, setRecaptchaVerified] = useState(false);
  
  const [authForm, setAuthForm] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    name: ''
  });

  const [view, setView] = useState('grid');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showFABMenu, setShowFABMenu] = useState(false);
  const [showActivation, setShowActivation] = useState(false);
  const [activationKey, setActivationKey] = useState('');
  const [userPlan, setUserPlan] = useState('free');
  const [storageUsed, setStorageUsed] = useState(0);
  const [files, setFiles] = useState([]);
  const [showUpload, setShowUpload] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentView, setCurrentView] = useState('home');
  const [showCreateFolder, setShowCreateFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');

  useEffect(() => {
    checkLoginStatus();
  }, []);

  useEffect(() => {
    if (isLoggedIn && currentUser) {
      loadUserData();
    }
  }, [isLoggedIn, currentUser]);

  useEffect(() => {
    if (isLoggedIn && currentUser) {
      saveUserData();
    }
  }, [files, userPlan, storageUsed, isLoggedIn, currentUser]);

  const checkLoginStatus = async () => {
    try {
      const sessionData = await window.storage.get('cloudvault_session');
      if (sessionData) {
        const session = JSON.parse(sessionData.value);
        setCurrentUser(session);
        setIsLoggedIn(true);
        setShowAuth(false);
      }
    } catch (error) {
      console.log('No active session');
    }
  };

  const loadUserData = async () => {
    if (!currentUser) return;
    
    try {
      const userKey = 'user_' + currentUser.id;
      const filesData = await window.storage.get(userKey + '_files');
      const planData = await window.storage.get(userKey + '_plan');
      const storageData = await window.storage.get(userKey + '_storage');
      
      if (filesData) setFiles(JSON.parse(filesData.value));
      if (planData) setUserPlan(planData.value);
      if (storageData) setStorageUsed(parseFloat(storageData.value));
    } catch (error) {
      console.log('Loading new user data');
    }
  };

  const saveUserData = async () => {
    if (!currentUser) return;
    
    try {
      const userKey = 'user_' + currentUser.id;
      await window.storage.set(userKey + '_files', JSON.stringify(files));
      await window.storage.set(userKey + '_plan', userPlan);
      await window.storage.set(userKey + '_storage', storageUsed.toString());
    } catch (error) {
      console.error('Error saving user data:', error);
    }
  };

  const hashPassword = async (password) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };

  const checkLoginAttempts = async () => {
    try {
      const attemptsData = await window.storage.get('login_attempts');
      if (attemptsData) {
        const attempts = JSON.parse(attemptsData.value);
        const now = Date.now();
        const oneHour = 60 * 60 * 1000;
        
        const recentAttempts = attempts.filter(time => now - time < oneHour);
        
        if (recentAttempts.length >= 5) {
          setShowRecaptcha(true);
          return false;
        }
        
        await window.storage.set('login_attempts', JSON.stringify([...recentAttempts, now]));
      } else {
        await window.storage.set('login_attempts', JSON.stringify([Date.now()]));
      }
      return true;
    } catch (error) {
      return true;
    }
  };

  const handleEmailAuth = async (e) => {
    e.preventDefault();
    setAuthError('');

    if (authMode === 'signup') {
      if (authForm.password !== authForm.confirmPassword) {
        setAuthError('Passwords do not match');
        return;
      }
      if (authForm.password.length < 8) {
        setAuthError('Password must be at least 8 characters');
        return;
      }
      if (!authForm.name.trim()) {
        setAuthError('Please enter your name');
        return;
      }
    }

    const canProceed = await checkLoginAttempts();
    if (!canProceed && !recaptchaVerified) {
      setAuthError('Too many login attempts. Please complete the reCAPTCHA verification.');
      return;
    }

    try {
      const hashedPassword = await hashPassword(authForm.password);
      
      if (authMode === 'signup') {
        const userId = 'user_' + Date.now();
        const newUser = {
          id: userId,
          email: authForm.email,
          name: authForm.name,
          provider: 'email',
          passwordHash: hashedPassword,
          createdAt: new Date().toISOString()
        };
        
        await window.storage.set('user_' + authForm.email, JSON.stringify(newUser));
        await window.storage.set('cloudvault_session', JSON.stringify(newUser));
        
        setCurrentUser(newUser);
        setIsLoggedIn(true);
        setShowAuth(false);
        alert('✓ Account created successfully!');
      } else {
        const userData = await window.storage.get('user_' + authForm.email);
        
        if (!userData) {
          setAuthError('Account not found. Please sign up.');
          return;
        }
        
        const user = JSON.parse(userData.value);
        
        if (user.passwordHash !== hashedPassword) {
          setAuthError('Invalid password');
          return;
        }
        
        await window.storage.set('cloudvault_session', JSON.stringify(user));
        setCurrentUser(user);
        setIsLoggedIn(true);
        setShowAuth(false);
        alert('✓ Logged in successfully!');
      }
    } catch (error) {
      setAuthError('An error occurred. Please try again.');
      console.error('Auth error:', error);
    }
  };

  const handleOAuthLogin = async (provider) => {
    const canProceed = await checkLoginAttempts();
    if (!canProceed && !recaptchaVerified) {
      setAuthError('Too many login attempts. Please complete the reCAPTCHA verification.');
      return;
    }

    const userId = provider + '_' + Date.now();
    const newUser = {
      id: userId,
      email: 'user@' + provider + '.com',
      name: provider.charAt(0).toUpperCase() + provider.slice(1) + ' User',
      provider: provider,
      createdAt: new Date().toISOString()
    };
    
    try {
      await window.storage.set('cloudvault_session', JSON.stringify(newUser));
      setCurrentUser(newUser);
      setIsLoggedIn(true);
      setShowAuth(false);
      alert('✓ Logged in with ' + provider + '!');
    } catch (error) {
      setAuthError('Failed to login with ' + provider);
    }
  };

  const handleLogout = async () => {
    try {
      await window.storage.delete('cloudvault_session');
      setCurrentUser(null);
      setIsLoggedIn(false);
      setShowAuth(true);
      setFiles([]);
      setStorageUsed(0);
      setUserPlan('free');
      alert('✓ Logged out successfully!');
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const handleRecaptchaVerify = () => {
    setRecaptchaVerified(true);
    setShowRecaptcha(false);
    alert('✓ reCAPTCHA verified! You can now login.');
  };

  const devKeys = ['X9a7BqL2mZ4tY8rN6wP3vC5dH0kR', 'M4nT7xQ2zV9gR1cW5bJ8sL0pF6yD3', 'A9xT3mQ7vL2pR8cW5yD0nK4zF6hJ1bU'];
  const maxKeys = ['Z7mK2xR9pL4vT8cQ1nW5yD6bF0sJ3hU', 'Z4nM8qR1xT7cV5pL9yD2wK6fH0jS3aE', 'C7vP2xL9mT4qR8nW1yD5kF0hJ6bZ3sU'];
  const proKeys = ['Q8mR2xL7vT9cW5yD1nK4zF6hJ0pS3aE', 'B5nT8qR1xV7cM9lY2wP6dH0jS4kZ3uC', 'L9vP3xN6mT4qR8cW1yD5kF0hJ7bZ2sU'];

  const getStorageLimit = () => {
    switch(userPlan) {
      case 'free': return 20;
      case 'pro': return 1000000;
      case 'max': return 2000000;
      case 'dev': return Infinity;
      default: return 20;
    }
  };

  const handleActivateKey = () => {
    const key = activationKey.trim();
    
    if (devKeys.includes(key)) {
      setUserPlan('dev');
      setShowActivation(false);
      setActivationKey('');
      alert('✓ Developer Plan Activated!');
    } else if (maxKeys.includes(key)) {
      setUserPlan('max');
      setShowActivation(false);
      setActivationKey('');
      alert('✓ MAX Plan Activated! 2TB Storage');
    } else if (proKeys.includes(key)) {
      setUserPlan('pro');
      setShowActivation(false);
      setActivationKey('');
      alert('✓ PRO Plan Activated! 1TB Storage');
    } else {
      alert('✗ Invalid activation key. Please try again.');
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const fileSizeMB = file.size / (1024 * 1024);
    const limit = getStorageLimit();
    const newUsed = storageUsed + fileSizeMB;
    
    if (newUsed > limit) {
      setUploadError('Storage limit exceeded! Upgrade your plan.');
      setTimeout(() => setUploadError(''), 5000);
      return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
      const newFile = {
        id: Date.now(),
        name: file.name,
        type: 'file',
        modified: new Date().toLocaleDateString(),
        size: fileSizeMB,
        data: e.target.result,
        category: currentView
      };

      setFiles([...files, newFile]);
      setStorageUsed(newUsed);
      setShowUpload(false);
      alert('✓ File uploaded!');
    };
    reader.readAsDataURL(file);
  };

  const handleCreateFolder = () => {
    if (!newFolderName.trim()) {
      alert('Please enter a folder name');
      return;
    }

    const newFolder = {
      id: Date.now(),
      name: newFolderName,
      type: 'folder',
      modified: new Date().toLocaleDateString(),
      size: 0,
      category: currentView
    };

    setFiles([...files, newFolder]);
    setNewFolderName('');
    setShowCreateFolder(false);
    alert('✓ Folder created!');
  };

  const handleDeleteFile = (fileId) => {
    const fileToDelete = files.find(f => f.id === fileId);
    if (fileToDelete && fileToDelete.type === 'file') {
      setStorageUsed(storageUsed - fileToDelete.size);
    }
    setFiles(files.filter(f => f.id !== fileId));
    alert('✓ File deleted!');
  };

  const handleDownloadFile = (file) => {
    if (file.type === 'folder') {
      alert('Cannot download folders');
      return;
    }

    const link = document.createElement('a');
    link.href = file.data;
    link.download = file.name;
    link.click();
    alert('✓ File downloaded!');
  };

  const getPlanBadge = () => {
    const badges = {
      free: { icon: Cloud, color: 'bg-gray-500', text: 'FREE' },
      pro: { icon: Crown, color: 'bg-purple-500', text: 'PRO' },
      max: { icon: Crown, color: 'bg-gradient-to-r from-yellow-400 to-orange-500', text: 'MAX' },
      dev: { icon: Shield, color: 'bg-gradient-to-r from-blue-500 to-cyan-500', text: 'DEV' }
    };
    return badges[userPlan];
  };

  const getFilteredFiles = () => {
    let filtered = files;
    if (currentView !== 'home' && currentView !== 'all') {
      filtered = filtered.filter(f => f.category === currentView);
    }
    if (searchQuery.trim()) {
      filtered = filtered.filter(f => 
        f.name.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    return filtered;
  };

  const storagePercent = (storageUsed / getStorageLimit()) * 100;
  const badge = getPlanBadge();
  const filteredFiles = getFilteredFiles();

  if (showAuth) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg">
              <Cloud className="w-10 h-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-800 mb-2">CloudVault</h1>
            <p className="text-gray-600">Secure cloud storage</p>
          </div>

          <div className="bg-white rounded-2xl shadow-xl p-8 border border-gray-100">
            <div className="flex gap-2 mb-6">
              <button
                onClick={() => {setAuthMode('login'); setAuthError('');}}
                className={'flex-1 py-3 rounded-xl font-semibold transition-all ' + (authMode === 'login' ? 'bg-blue-500 text-white shadow-md' : 'bg-gray-100 text-gray-600')}
              >
                Login
              </button>
              <button
                onClick={() => {setAuthMode('signup'); setAuthError('');}}
                className={'flex-1 py-3 rounded-xl font-semibold transition-all ' + (authMode === 'signup' ? 'bg-blue-500 text-white shadow-md' : 'bg-gray-100 text-gray-600')}
              >
                Sign Up
              </button>
            </div>

            {authError && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                {authError}
              </div>
            )}

            {showRecaptcha && (
              <div className="mb-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                <p className="text-sm text-yellow-800 mb-3">Too many attempts. Verify you are human.</p>
                <div className="bg-white border-2 border-gray-300 rounded-lg p-4 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <input type="checkbox" onChange={handleRecaptchaVerify} className="w-6 h-6" />
                    <span className="text-sm font-medium">I am not a robot</span>
                  </div>
                  <div className="text-xs text-gray-500">
                    <div>reCAPTCHA</div>
                  </div>
                </div>
              </div>
            )}

            <form onSubmit={handleEmailAuth} className="space-y-4">
              {authMode === 'signup' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Full Name</label>
                  <input
                    type="text"
                    value={authForm.name}
                    onChange={(e) => setAuthForm({...authForm, name: e.target.value})}
                    placeholder="John Doe"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="email"
                    value={authForm.email}
                    onChange={(e) => setAuthForm({...authForm, email: e.target.value})}
                    placeholder="you@example.com"
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={authForm.password}
                    onChange={(e) => setAuthForm({...authForm, password: e.target.value})}
                    placeholder="••••••••"
                    className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {authMode === 'signup' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Confirm Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={authForm.confirmPassword}
                      onChange={(e) => setAuthForm({...authForm, confirmPassword: e.target.value})}
                      placeholder="••••••••"
                      className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                      required
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white py-3 rounded-xl font-semibold hover:from-blue-600 hover:to-purple-700 transition-all shadow-md"
              >
                {authMode === 'login' ? 'Login' : 'Create Account'}
              </button>
            </form>

            <div className="my-6 flex items-center gap-4">
              <div className="flex-1 h-px bg-gray-200"></div>
              <span className="text-sm text-gray-500 font-medium">OR</span>
              <div className="flex-1 h-px bg-gray-200"></div>
            </div>

            <div className="space-y-3">
              <button
                onClick={() => handleOAuthLogin('google')}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 border-2 border-gray-300 rounded-xl hover:bg-gray-50 transition-all font-medium text-gray-700"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Continue with Google
              </button>

              <button
                onClick={() => handleOAuthLogin('microsoft')}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 border-2 border-gray-300 rounded-xl hover:bg-gray-50 transition-all font-medium text-gray-700"
              >
                <svg className="w-5 h-5" viewBox="0 0 23 23">
                  <path fill="#f35325" d="M0 0h11v11H0z"/>
                  <path fill="#81bc06" d="M12 0h11v11H12z"/>
                  <path fill="#05a6f0" d="M0 12h11v11H0z"/>
                  <path fill="#ffba08" d="M12 12h11v11H12z"/>
                </svg>
                Continue with Microsoft
              </button>

              <button
                onClick={() => handleOAuthLogin('apple')}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 border-2 border-gray-300 rounded-xl hover:bg-gray-50 transition-all font-medium text-gray-700"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09l.01-.01zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/>
                </svg>
                Continue with Apple
              </button>
            </div>

            <p className="mt-6 text-center text-xs text-gray-500">
              Encrypted with TLS 1.3
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen bg-gray-50 flex flex-col overflow-hidden">
      <div className="bg-white border-b border-gray-200 px-4 py-3 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-3">
          <button onClick={() => setSidebarOpen(!sidebarOpen)} className="p-2 hover:bg-gray-100 rounded-lg">
            <Menu className="w-5 h-5 text-gray-600" />
          </button>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-400 to-blue-600 rounded-lg flex items-center justify-center shadow-md">
              <Cloud className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-semibold text-gray-800">CloudVault</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="p-2 hover:bg-gray-100 rounded-lg">
            <Search className="w-5 h-5 text-gray-600" />
          </button>
          <div className="relative group">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-400 to-purple-500 rounded-full flex items-center justify-center text-white font-semibold cursor-pointer">
              {currentUser && currentUser.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}
            </div>
            <div className="absolute right-0 top-12 bg-white rounded-xl shadow-2xl border border-gray-200 p-4 min-w-[250px] opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
              <div className="flex items-center gap-3 mb-3 pb-3 border-b border-gray-200">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-400 to-purple-500 rounded-full flex items-center justify-center text-white font-bold text-lg">
                  {currentUser && currentUser.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}
                </div>
                <div>
                  <div className="font-semibold text-gray-800">{currentUser ? currentUser.name : 'User'}</div>
                  <div className="text-xs text-gray-500">{currentUser ? currentUser.email : 'email'}</div>
                  <div className="text-xs text-blue-600 mt-1">via {currentUser ? currentUser.provider : 'email'}</div>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors font-medium"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className={'fixed inset-y-0 left-0 w-64 bg-white border-r border-gray-200 z-50 transition-transform duration-300 lg:translate-x-0 lg:static flex flex-col shadow-lg ' + (sidebarOpen ? 'translate-x-0' : '-translate-x-full')}>
          <div className="p-4 border-b border-gray-200">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-400 to-purple-500 rounded-full flex items-center justify-center text-white font-bold text-lg">
                {currentUser && currentUser.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}
              </div>
              <div className="flex-1">
                <div className="font-semibold text-gray-800">{currentUser ? currentUser.name : 'User'}</div>
                <div className="text-xs text-gray-500">{currentUser ? currentUser.email : 'email'}</div>
              </div>
            </div>
            <div className={'text-white px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-2 shadow-md ' + badge.color}>
              <badge.icon className="w-4 h-4" />
              {badge.text} PLAN
            </div>
          </div>

          <nav className="flex-1 overflow-y-auto py-4">
            <NavItem icon={Home} text="Home" active={currentView === 'home'} onClick={() => setCurrentView('home')} />
            <NavItem icon={Clock} text="Recent" active={currentView === 'recent'} onClick={() => setCurrentView('recent')} />
            <NavItem icon={HardDrive} text="All Files" active={currentView === 'all'} onClick={() => setCurrentView('all')} />
            <NavItem icon={Users} text="Shared" active={currentView === 'shared'} onClick={() => setCurrentView('shared')} />
            <NavItem icon={Star} text="Favorites" active={currentView === 'favorites'} onClick={() => setCurrentView('favorites')} />
            <NavItem icon={CloudOff} text="Offline Files" active={currentView === 'offline'} onClick={() => setCurrentView('offline')} />
            <NavItem icon={Archive} text="Backups" active={currentView === 'backups'} onClick={() => setCurrentView('backups')} />
            <NavItem icon={Trash2} text="Trash" active={currentView === 'trash'} onClick={() => setCurrentView('trash')} />
          </nav>

          <div className="p-4 border-t border-gray-200">
            <button 
              onClick={() => setShowActivation(true)}
              className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white py-2.5 rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 transition-all mb-3 flex items-center justify-center gap-2 shadow-md"
            >
              <Key className="w-4 h-4" />
              Activate Plan
            </button>
            <div className="text-xs text-gray-600 mb-2">Storage Used</div>
            <div className="flex justify-between text-xs text-gray-700 mb-1 font-semibold">
              <span>{storageUsed.toFixed(2)}MB</span>
              <span>{getStorageLimit() === Infinity ? '∞' : getStorageLimit() + 'MB'}</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
              <div 
                className={'h-full rounded-full transition-all duration-500 ' + (storagePercent > 90 ? 'bg-red-500' : storagePercent > 70 ? 'bg-yellow-500' : 'bg-blue-500')}
                style={{ width: Math.min(storagePercent, 100) + '%' }}
              />
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          <div className="p-6">
            <div className="mb-6 flex gap-3">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search files (type to filter)"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                    }
                  }}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                )}
              </div>
              <div className="flex bg-white border border-gray-300 rounded-xl overflow-hidden">
                <button
                  onClick={() => setView('grid')}
                  className={'p-3 transition-colors ' + (view === 'grid' ? 'bg-blue-500 text-white' : 'text-gray-600 hover:bg-gray-100')}
                >
                  <Grid className="w-5 h-5" />
                </button>
                <button
                  onClick={() => setView('list')}
                  className={'p-3 transition-colors ' + (view === 'list' ? 'bg-blue-500 text-white' : 'text-gray-600 hover:bg-gray-100')}
                >
                  <List className="w-5 h-5" />
                </button>
              </div>
            </div>

            {uploadError && (
              <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 mt-0.5" />
                <div>
                  <div className="font-semibold mb-1">Storage Limit Reached</div>
                  <div className="text-sm">{uploadError}</div>
                </div>
              </div>
            )}

            {filteredFiles.length === 0 ? (
              <div className="text-center py-12">
                <Cloud className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                <p className="text-gray-500 text-lg mb-2">No files yet</p>
                <p className="text-gray-400 text-sm">Upload your first file to get started</p>
              </div>
            ) : (
              <div className={view === 'grid' ? 'grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4' : 'space-y-2'}>
                {filteredFiles.map(file => (
                  <FileItem 
                    key={file.id} 
                    file={file} 
                    view={view}
                    onDelete={() => handleDeleteFile(file.id)}
                    onDownload={() => handleDownloadFile(file)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="lg:hidden bg-white border-t border-gray-200 px-4 py-2 flex justify-around shadow-lg">
        <BottomNavItem icon={Home} text="Home" active={currentView === 'home'} onClick={() => setCurrentView('home')} />
        <BottomNavItem icon={Star} text="Favorites" active={currentView === 'favorites'} onClick={() => setCurrentView('favorites')} />
        <BottomNavItem icon={Users} text="Shared" active={currentView === 'shared'} onClick={() => setCurrentView('shared')} />
        <BottomNavItem icon={HardDrive} text="Files" active={currentView === 'all'} onClick={() => setCurrentView('all')} />
      </div>

      <button
        onClick={() => setShowFABMenu(!showFABMenu)}
        className="fixed bottom-20 right-6 lg:bottom-6 w-14 h-14 bg-gradient-to-br from-blue-500 to-purple-600 text-white rounded-full shadow-2xl hover:shadow-3xl transition-all hover:scale-110 flex items-center justify-center z-40"
      >
        {showFABMenu ? <X className="w-6 h-6" /> : <Plus className="w-6 h-6" />}
      </button>

      {showFABMenu && (
        <div className="fixed bottom-36 right-6 lg:bottom-24 bg-white rounded-2xl shadow-2xl p-3 z-40 min-w-[200px]">
          <FABMenuItem icon={FolderPlus} text="Create Folder" onClick={() => {setShowCreateFolder(true); setShowFABMenu(false);}} />
          <FABMenuItem icon={Upload} text="Upload File" onClick={() => {setShowUpload(true); setShowFABMenu(false);}} />
        </div>
      )}

      {showUpload && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-xl font-bold mb-4 text-gray-800">Upload File</h3>
            <input
              type="file"
              onChange={handleFileUpload}
              className="w-full mb-4 p-3 border border-gray-300 rounded-lg"
            />
            <button onClick={() => setShowUpload(false)} className="w-full bg-gray-200 text-gray-700 py-3 rounded-lg hover:bg-gray-300 transition-colors">Cancel</button>
          </div>
        </div>
      )}

      {showCreateFolder && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl">
            <h3 className="text-xl font-bold mb-4 text-gray-800">Create Folder</h3>
            <input
              type="text"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              placeholder="Folder name"
              className="w-full mb-4 p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <div className="flex gap-3">
              <button onClick={handleCreateFolder} className="flex-1 bg-blue-500 text-white py-3 rounded-lg hover:bg-blue-600 transition-colors">Create</button>
              <button onClick={() => {setShowCreateFolder(false); setNewFolderName('');}} className="flex-1 bg-gray-200 text-gray-700 py-3 rounded-lg hover:bg-gray-300 transition-colors">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {showActivation && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                <Key className="w-6 h-6 text-white" />
              </div>
              <h3 className="text-xl font-bold text-gray-800">Activate Plan</h3>
            </div>
            
            <p className="text-gray-600 mb-4">Enter your activation key to upgrade</p>
            
            <input
              type="text"
              value={activationKey}
              onChange={(e) => setActivationKey(e.target.value)}
              placeholder="Enter activation key"
              className="w-full px-4 py-3 border border-gray-300 rounded-xl mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            
            <div className="bg-gray-50 rounded-xl p-4 mb-4 text-sm">
              <div className="font-semibold text-gray-800 mb-2">Available Plans:</div>
              <div className="space-y-1 text-gray-600">
                <div>• <span className="font-semibold text-purple-600">PRO</span> - 1TB ($50 CAD)</div>
                <div>• <span className="font-semibold text-orange-600">MAX</span> - 2TB ($150 CAD)</div>
                <div>• <span className="font-semibold text-cyan-600">DEV</span> - Unlimited (Key Only)</div>
              </div>
            </div>
            
            <div className="flex gap-3">
              <button
                onClick={handleActivateKey}
                className="flex-1 bg-gradient-to-r from-blue-500 to-purple-600 text-white py-3 rounded-xl font-semibold hover:from-blue-600 hover:to-purple-700 transition-all"
              >
                Activate
              </button>
              <button
                onClick={() => {setShowActivation(false); setActivationKey('');}}
                className="flex-1 bg-gray-200 text-gray-700 py-3 rounded-xl font-semibold hover:bg-gray-300 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
};

const NavItem = ({ icon: Icon, text, active, onClick }) => (
  <button onClick={onClick} className={'w-full flex items-center gap-3 px-4 py-3 transition-all ' + (active ? 'bg-blue-50 text-blue-600 border-r-4 border-blue-600' : 'text-gray-700 hover:bg-gray-50')}>
    <Icon className="w-5 h-5" />
    <span className="font-medium">{text}</span>
  </button>
);

const FileItem = ({ file, view, onDelete, onDownload }) => {
  const [showMenu, setShowMenu] = useState(false);
  const isFolder = file.type === 'folder';
  
  if (view === 'grid') {
    return (
      <div className="bg-white rounded-xl p-4 border border-gray-200 hover:shadow-lg hover:border-blue-300 transition-all cursor-pointer group relative">
        <div className={'w-full h-24 rounded-lg mb-3 flex items-center justify-center ' + (isFolder ? 'bg-gradient-to-br from-blue-400 to-blue-600' : 'bg-gradient-to-br from-gray-100 to-gray-200')}>
          {isFolder ? <Folder className="w-12 h-12 text-white" /> : <File className="w-12 h-12 text-gray-500" />}
        </div>
        <div className="font-medium text-gray-800 truncate group-hover:text-blue-600 transition-colors">{file.name}</div>
        <div className="text-xs text-gray-500 mt-1">{file.modified}</div>
        <button 
          onClick={(e) => {e.stopPropagation(); setShowMenu(!showMenu);}}
          className="absolute top-2 right-2 p-2 hover:bg-gray-100 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <MoreVertical className="w-4 h-4 text-gray-600" />
        </button>
        {showMenu && (
          <div className="absolute top-12 right-2 bg-white rounded-lg shadow-xl border border-gray-200 py-2 z-10 min-w-[150px]">
            {!isFolder && <button onClick={(e) => {e.stopPropagation(); onDownload(); setShowMenu(false);}} className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-2 text-sm"><Download className="w-4 h-4" />Download</button>}
            <button onClick={(e) => {e.stopPropagation(); onDelete(); setShowMenu(false);}} className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-2 text-sm text-red-600"><Trash2 className="w-4 h-4" />Delete</button>
          </div>
        )}
      </div>
    );
  }
  
  return (
    <div className="bg-white rounded-lg p-4 border border-gray-200 hover:bg-gray-50 transition-all cursor-pointer flex items-center gap-3 group relative">
      <div className={'w-10 h-10 rounded-lg flex items-center justify-center ' + (isFolder ? 'bg-blue-100' : 'bg-gray-100')}>
        {isFolder ? <Folder className="w-5 h-5 text-blue-600" /> : <File className="w-5 h-5 text-gray-600" />}
      </div>
      <div className="flex-1">
        <div className="font-medium text-gray-800 group-hover:text-blue-600 transition-colors">{file.name}</div>
        <div className="text-xs text-gray-500">{file.modified} • {file.size.toFixed(2)}MB</div>
      </div>
      <button onClick={(e) => {e.stopPropagation(); setShowMenu(!showMenu);}} className="p-2 hover:bg-gray-100 rounded-lg">
        <MoreVertical className="w-5 h-5 text-gray-500" />
      </button>
      {showMenu && (
        <div className="absolute top-12 right-2 bg-white rounded-lg shadow-xl border border-gray-200 py-2 z-10 min-w-[150px]">
          {!isFolder && <button onClick={(e) => {e.stopPropagation(); onDownload(); setShowMenu(false);}} className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-2 text-sm"><Download className="w-4 h-4" />Download</button>}
          <button onClick={(e) => {e.stopPropagation(); onDelete(); setShowMenu(false);}} className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-2 text-sm text-red-600"><Trash2 className="w-4 h-4" />Delete</button>
        </div>
      )}
    </div>
  );
};

const BottomNavItem = ({ icon: Icon, text, active, onClick }) => (
  <button onClick={onClick} className={'flex flex-col items-center gap-1 py-2 px-4 ' + (active ? 'text-blue-600' : 'text-gray-500')}>
    <Icon className="w-6 h-6" />
    <span className="text-xs font-medium">{text}</span>
  </button>
);

const FABMenuItem = ({ icon: Icon, text, onClick }) => (
  <button onClick={onClick} className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-50 rounded-lg transition-colors text-left">
    <Icon className="w-5 h-5 text-gray-700" />
    <span className="text-gray-800 font-medium">{text}</span>
  </button>
);

export default CloudStorageApp;