import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import * as authApi from '../api/auth.api';
import PasswordInput from '../components/PasswordInput';

const Register = () => {
  const [name, setName]                       = useState('');
  const [email, setEmail]                     = useState('');
  const [password, setPassword]               = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMsg, setErrorMsg]               = useState(null);
  const [successMsg, setSuccessMsg]           = useState(null);
  const [submitting, setSubmitting]           = useState(false);

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (password !== confirmPassword) {
      setErrorMsg('Passwords do not match.');
      return;
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{10,}$/;
    if (!passwordRegex.test(password)) {
      setErrorMsg('Password must be at least 10 characters and contain an uppercase letter, a lowercase letter, a number, and a special character.');
      return;
    }

    setSubmitting(true);
    try {
      await authApi.register({ name, email, password });
      setSuccessMsg('Account created! Redirecting to login…');
      setTimeout(() => navigate('/login'), 1500);
    } catch (error) {
      setErrorMsg(error.message || 'Registration failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const passwordsMatch = confirmPassword.length > 0 && password === confirmPassword;
  const passwordsMismatch = confirmPassword.length > 0 && password !== confirmPassword;

  return (
    <div className="min-h-screen w-full flex bg-slate-50 selection:bg-indigo-100 selection:text-indigo-900">
      {/* Premium Left Panel - Branding */}
      <div className="hidden lg:flex flex-col flex-1 bg-[#0a0f1c] border-r border-slate-800/60 relative overflow-hidden">
        {/* Layer 1: Ambient Gradients (Gives depth and visual identity) */}
        <div className="absolute -top-[20%] -left-[10%] w-[70%] h-[70%] rounded-full bg-indigo-600/10 blur-[120px] mix-blend-screen pointer-events-none" />
        <div className="absolute -bottom-[20%] -right-[10%] w-[60%] h-[60%] rounded-full bg-sky-500/10 blur-[100px] mix-blend-screen pointer-events-none" />

        {/* Layer 2: Subtle Mesh Grid */}
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxwYXRoIGQ9Ik0wIDBoMjR2MjRIMHoiIGZpbGw9Im5vbmUiLz4KPHBhdGggZD0iTTExLjUgMjRWMGgxdjI0aC0xeiIgZmlsbD0icmdiYSgyNTUsMjU1LDI1NSwwLjAyKSIvPgo8cGF0aCBkPSJNMCAxMS41aDI0djFoLTI0di0xeiIgZmlsbD0icmdiYSgyNTUsMjU1LDI1NSwwLjAyKSIvPgo8L3N2Zz4=')] opacity-60 mix-blend-overlay"></div>

        {/* Layer 3: Content */}
        <div className="relative z-10 p-12 xl:p-16 flex flex-col h-full justify-between">
          <div className="flex items-center gap-3 select-none">
            <div className="flex items-center justify-center w-8 h-8 rounded-[6px] bg-gradient-to-b from-indigo-500 to-indigo-600 shadow-sm border border-indigo-400/30">
               <span className="text-white text-xs font-bold leading-none">✦</span>
            </div>
            <span className="text-white font-medium tracking-wide text-sm">IAM Platform</span>
          </div>

          <div className="max-w-[420px] mt-auto mb-20 space-y-8">
            <h1 className="text-[34px] font-semibold tracking-tight text-white leading-[1.15]">
              Secure foundation <br/> for your team.
            </h1>
            
            <div className="space-y-5">
              <div className="flex items-start gap-4 opacity-80 hover:opacity-100 transition-opacity duration-300">
                 <div className="mt-1 w-5 h-5 shrink-0 rounded-full bg-indigo-500/10 flex items-center justify-center border border-indigo-500/20">
                    <svg className="w-3 h-3 text-indigo-400" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                 </div>
                 <p className="text-[14px] text-slate-300 font-medium leading-relaxed">Multi-Factor Authentication and contextual policies baked in by default.</p>
              </div>
              <div className="flex items-start gap-4 opacity-80 hover:opacity-100 transition-opacity duration-300">
                 <div className="mt-1 w-5 h-5 shrink-0 rounded-full bg-sky-500/10 flex items-center justify-center border border-sky-500/20">
                    <svg className="w-3 h-3 text-sky-400" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                 </div>
                 <p className="text-[14px] text-slate-300 font-medium leading-relaxed">Centralized active session modeling and continuous threat introspection.</p>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between text-[13px] font-medium text-slate-500/80 border-t border-slate-800/50 pt-6">
            <span>&copy; {new Date().getFullYear()} Security Infrastructure</span>
            <div className="flex items-center gap-5">
               <a href="#" className="hover:text-slate-300 transition-colors duration-200">System Status</a>
               <a href="#" className="hover:text-slate-300 transition-colors duration-200">Privacy Policy</a>
            </div>
          </div>
        </div>
      </div>

      {/* Right Panel - Form Container (elevated, asymmetric depth) */}
      <div className="flex-1 flex flex-col justify-center bg-white px-6 py-12 sm:px-8 lg:flex-none lg:w-[560px] xl:w-[640px] relative shadow-2xl shadow-slate-900/5 z-20 font-sans">
        
        {/* Absolute Trust Signal */}
        <div className="hidden sm:flex absolute top-8 right-10 items-center gap-2 text-[13px] font-medium text-slate-400 select-none">
          <svg className="w-3.5 h-3.5 text-emerald-500" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"></path></svg>
          Encrypted Connection
        </div>

        <div className="mx-auto w-full max-w-[400px]">
          {/* Mobile Header */}
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="flex items-center justify-center w-7 h-7 rounded-[6px] bg-gradient-to-b from-indigo-500 to-indigo-600 shadow-sm border border-indigo-400">
               <span className="text-white text-[10px] font-bold">✦</span>
            </div>
            <span className="text-slate-900 font-medium tracking-tight text-sm">IAM Platform</span>
          </div>

          <div className="mb-8">
            <h2 className="text-[26px] font-semibold text-slate-900 tracking-tight">Create your account</h2>
            <p className="mt-2 text-[14px] text-slate-500 font-medium leading-relaxed">
              Join the platform to orchestrate your identity layer natively.
            </p>
          </div>

          <div>
            {errorMsg && (
              <div className="mb-6 bg-red-50/80 text-red-700 px-4 py-3.5 rounded-[8px] text-[13px] font-medium border border-red-200/60 flex items-start shadow-sm animate-in fade-in slide-in-from-top-2 duration-200">
                <span className="mr-2.5 text-red-500 shrink-0 mt-0.5">
                   <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" /></svg>
                </span>
                <span className="leading-relaxed">{errorMsg}</span>
              </div>
            )}
            {successMsg && (
              <div className="mb-6 bg-emerald-50/80 text-emerald-700 px-4 py-3.5 rounded-[8px] text-[13px] font-medium border border-emerald-200/60 flex items-start shadow-sm animate-in fade-in slide-in-from-top-2 duration-200">
                <span className="mr-2.5 text-emerald-500 shrink-0 mt-0.5">
                   <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" /></svg>
                </span>
                <span className="leading-relaxed">{successMsg}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              <div className="group">
                <label htmlFor="reg-name" className="block text-[13px] font-medium text-slate-700 mb-1.5 transition-colors group-focus-within:text-indigo-600">
                  Full name
                </label>
                <div className="relative">
                  <input
                    id="reg-name"
                    type="text"
                    className="block w-full rounded-[6px] border-0 py-2.5 px-3.5 text-[14px] text-slate-900 bg-slate-50/50 shadow-sm ring-1 ring-inset ring-slate-200/80 placeholder:text-slate-400 focus:bg-white focus:ring-2 focus:ring-inset focus:ring-indigo-600 hover:ring-slate-300 transition-all duration-200 outline-none"
                    placeholder="Jane Smith"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    autoComplete="name"
                    required
                    minLength={2}
                  />
                </div>
              </div>

              <div className="group">
                <label htmlFor="reg-email" className="block text-[13px] font-medium text-slate-700 mb-1.5 transition-colors group-focus-within:text-indigo-600">
                  Email address
                </label>
                <div className="relative">
                  <input
                    id="reg-email"
                    type="email"
                    className="block w-full rounded-[6px] border-0 py-2.5 px-3.5 text-[14px] text-slate-900 bg-slate-50/50 shadow-sm ring-1 ring-inset ring-slate-200/80 placeholder:text-slate-400 focus:bg-white focus:ring-2 focus:ring-inset focus:ring-indigo-600 hover:ring-slate-300 transition-all duration-200 outline-none"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                  />
                </div>
              </div>

              <div className="group">
                <label htmlFor="reg-password" className="block text-[13px] font-medium text-slate-700 mb-1.5 transition-colors group-focus-within:text-indigo-600">
                  Password
                </label>
                <div className="relative">
                  <PasswordInput
                    id="reg-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 10 characters"
                    autoComplete="new-password"
                    showStrength
                    className="block w-full rounded-[6px] border-0 py-2.5 px-3.5 text-[14px] text-slate-900 bg-slate-50/50 shadow-sm ring-1 ring-inset ring-slate-200/80 placeholder:text-slate-400 focus:bg-white focus:ring-2 focus:ring-inset focus:ring-indigo-600 hover:ring-slate-300 transition-all duration-200 outline-none"
                  />
                </div>
              </div>

              <div className="group">
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="reg-confirm" className="block text-[13px] font-medium text-slate-700 transition-colors group-focus-within:text-indigo-600">
                    Confirm password
                  </label>
                  {passwordsMatch && <span className="text-emerald-500 text-[12px] font-medium animate-in fade-in slide-in-from-bottom-1 flex items-center gap-1"><span className="text-[10px]">✓</span> Match</span>}
                  {passwordsMismatch && <span className="text-red-500 text-[12px] font-medium animate-in fade-in slide-in-from-bottom-1 flex items-center gap-1"><span className="text-[10px]">✕</span> Mismatch</span>}
                </div>
                <div className="relative">
                  <PasswordInput
                    id="reg-confirm"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat your password"
                    autoComplete="new-password"
                    className={`block w-full rounded-[6px] border-0 py-2.5 px-3.5 text-[14px] text-slate-900 shadow-sm ring-1 ring-inset placeholder:text-slate-400 focus:bg-white focus:ring-2 focus:ring-inset outline-none transition-all duration-200 ${
                      passwordsMismatch 
                        ? 'bg-red-50/50 ring-red-300 focus:ring-red-500 hover:ring-red-400' 
                        : passwordsMatch 
                          ? 'bg-emerald-50/50 ring-emerald-300 focus:ring-emerald-500 hover:ring-emerald-400'
                          : 'bg-slate-50/50 ring-slate-200/80 focus:ring-indigo-600 hover:ring-slate-300'
                    }`}
                  />
                </div>
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  className="relative flex w-full justify-center items-center rounded-[6px] bg-indigo-600 px-3.5 py-2.5 text-[14px] font-medium text-white shadow-[0_1px_2px_rgba(79,70,229,0.3)] hover:bg-indigo-500 hover:shadow-md hover:-translate-y-[0.5px] active:translate-y-[0.5px] active:scale-[0.99] transition-all duration-200 border border-transparent outline-none disabled:opacity-70 disabled:cursor-not-allowed group overflow-hidden"
                  disabled={submitting}
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent translate-x-[-100%] group-hover:animate-[shine_1.5s_ease-out_infinite]" />
                  {submitting ? (
                    <span className="flex items-center gap-2">
                       <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                       Creating...
                    </span>
                  ) : 'Create account'}
                </button>
              </div>
            </form>

            <p className="mt-8 text-center text-[14px] text-slate-500 font-medium tracking-tight">
              Already have an account?{' '}
              <Link to="/login" className="font-semibold text-indigo-600 hover:text-indigo-500 hover:underline underline-offset-4 transition-colors">
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
