import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import PasswordInput from '../components/PasswordInput';

const Login = () => {
  const [email, setEmail]         = useState('');
  const [password, setPassword]   = useState('');
  const [errorMsg, setErrorMsg]   = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const { login } = useAuth();

  const location = useLocation();
  const navigate  = useNavigate();
  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const result = await login(email, password);
      if (result.mfaRequired) {
        navigate('/mfa');
      } else if (result.success) {
        if (result.user?.role === 'ADMIN' && result.user?.totpEnabled === false) {
          navigate('/profile', { replace: true });
        } else {
          navigate(from, { replace: true });
        }
      }
    } catch (error) {
      console.error('Login error', error);
      setErrorMsg(error.message || 'An error occurred during login');
    } finally {
      setSubmitting(false);
    }
  };

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
              Identity infrastructure <br/> for scale.
            </h1>
            
            <div className="space-y-5">
              <div className="flex items-start gap-4 opacity-80 hover:opacity-100 transition-opacity duration-300">
                 <div className="mt-1 w-5 h-5 shrink-0 rounded-full bg-indigo-500/10 flex items-center justify-center border border-indigo-500/20">
                    <svg className="w-3 h-3 text-indigo-400" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                 </div>
                 <p className="text-[14px] text-slate-300 font-medium leading-relaxed">Enterprise SAML & OAuth connections natively bridged with minimal friction.</p>
              </div>
              <div className="flex items-start gap-4 opacity-80 hover:opacity-100 transition-opacity duration-300">
                 <div className="mt-1 w-5 h-5 shrink-0 rounded-full bg-sky-500/10 flex items-center justify-center border border-sky-500/20">
                    <svg className="w-3 h-3 text-sky-400" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                 </div>
                 <p className="text-[14px] text-slate-300 font-medium leading-relaxed">Granular RBAC provisioning and zero-trust perimeter boundaries natively.</p>
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
          Secure Connection SSL
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
            <h2 className="text-[26px] font-semibold text-slate-900 tracking-tight">Welcome back</h2>
            <p className="mt-2 text-[14px] text-slate-500 font-medium leading-relaxed">
              Enter your credentials to access the console.
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

            <form onSubmit={handleSubmit} className="space-y-5" noValidate>
              <div className="group">
                <label flex="true" htmlFor="login-email" className="block text-[13px] font-medium text-slate-700 mb-1.5 transition-colors group-focus-within:text-indigo-600">
                  Email address
                </label>
                <div className="relative">
                  <input
                    id="login-email"
                    type="email"
                    className="block w-full rounded-[6px] border-0 py-2.5 px-3.5 text-[14px] text-slate-900 bg-slate-50/50 shadow-sm ring-1 ring-inset ring-slate-200/80 placeholder:text-slate-400 focus:bg-white focus:ring-2 focus:ring-inset focus:ring-indigo-600 hover:ring-slate-300 transition-all duration-200 outline-none"
                    placeholder="name@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                  />
                </div>
              </div>

              <div className="group">
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="login-password" className="block text-[13px] font-medium text-slate-700 transition-colors group-focus-within:text-indigo-600">
                    Password
                  </label>
                  <a href="#" className="text-[12px] font-medium text-indigo-600 hover:text-indigo-500 transition-colors">Forgot password?</a>
                </div>
                <div className="relative">
                  <PasswordInput
                    id="login-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    className="block w-full rounded-[6px] border-0 py-2.5 px-3.5 text-[14px] text-black bg-slate-50/50 shadow-sm ring-1 ring-inset ring-slate-200/80 placeholder:text-slate-400 focus:bg-white focus:ring-2 focus:ring-inset focus:ring-indigo-600 hover:ring-slate-300 transition-all duration-200 outline-none"
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="relative flex w-full justify-center items-center rounded-[6px] bg-indigo-600 px-3.5 py-2.5 text-[14px] font-medium text-white shadow-[0_1px_2px_rgba(79,70,229,0.3)] hover:bg-indigo-500 hover:shadow-md hover:-translate-y-[0.5px] active:translate-y-[0.5px] active:scale-[0.99] transition-all duration-200 border border-transparent outline-none disabled:opacity-70 disabled:cursor-not-allowed group overflow-hidden"
                  disabled={submitting}
                >
                  {/* Subtle shine effect on button */}
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent translate-x-[-100%] group-hover:animate-[shine_1.5s_ease-out_infinite]" />
                  
                  {submitting ? (
                    <span className="flex items-center gap-2">
                      <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                      Authenticating...
                    </span>
                  ) : 'Sign in to Console'}
                </button>
              </div>
            </form>

            <div className="mt-8">
              <div className="relative">
                <div className="absolute inset-0 flex items-center" aria-hidden="true">
                  <div className="w-full border-t border-slate-100" />
                </div>
                <div className="relative flex justify-center text-[12px] font-medium uppercase tracking-wider">
                  <span className="bg-white px-4 text-slate-400">or continue with</span>
                </div>
              </div>

              <div className="mt-6">
                <a
                  href="/api/v1/auth/google"
                  className="flex w-full items-center justify-center gap-3 rounded-[6px] bg-white px-3.5 py-2.5 text-[14px] font-medium text-slate-700 shadow-sm ring-1 ring-inset ring-slate-200/80 hover:bg-slate-50 hover:ring-slate-300 hover:text-slate-900 transition-all duration-200 active:scale-[0.99] outline-none focus-visible:ring-2 focus-visible:ring-indigo-600 focus-visible:ring-offset-2"
                >
                  <svg className="h-[18px] w-[18px]" viewBox="0 0 24 24" aria-hidden="true">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  Google
                </a>
              </div>
            </div>
            
            <p className="mt-8 text-center text-[14px] text-slate-500 font-medium">
              Don't have an account?{' '}
              <Link to="/register" className="font-semibold text-indigo-600 hover:text-indigo-500 hover:underline underline-offset-4 transition-colors">
                Request access
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
