import { useEffect, useRef, useState } from 'react'
import { ShieldCheck, LockKeyhole, FileText, Upload, Search, Users, Activity, LogOut, Download, Share2, Trash2, RefreshCw, CheckCircle2, AlertTriangle, FolderOpen, X, BarChart3, Settings, History, ClipboardCheck, ShieldAlert, Fingerprint, MonitorSmartphone, BellRing, KeyRound, Eye, EyeOff } from 'lucide-react'
import api, { errorMessage } from './api/client'

const initialFilters = { search: '', category: '', owner: '', date_from: '', date_to: '', file_type: '', permission: '', hash_prefix: '', sort_by: 'created_at', sort_order: 'desc' }

export default function App() {
  const [user, setUser] = useState(null)
  const googleButtonRef = useRef(null)
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || ''
  const [authMode, setAuthMode] = useState('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [fullName, setFullName] = useState('')
  const [otp, setOtp] = useState('')
  const [page, setPage] = useState('documents')
  const [docs, setDocs] = useState([])
  const [users, setUsers] = useState([])
  const [audit, setAudit] = useState([])
  const [auditFilters, setAuditFilters] = useState({ action: '', outcome: '', actor_id: '' })
  const [approvals, setApprovals] = useState([])
  const [analytics, setAnalytics] = useState(null)
  const [filters, setFilters] = useState(initialFilters)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState(null)
  const [grants, setGrants] = useState([])
  const [grantEmail, setGrantEmail] = useState('')
  const [grantPermission, setGrantPermission] = useState('read')
  const [grantExpiry, setGrantExpiry] = useState('')
  const [title, setTitle] = useState('')
  const [category, setCategory] = useState('General')
  const [requiresApproval, setRequiresApproval] = useState(false)
  const [file, setFile] = useState(null)
  const [versionFile, setVersionFile] = useState(null)
  const [versionNote, setVersionNote] = useState('')
  const [versions, setVersions] = useState([])
  const [integrity, setIntegrity] = useState(null)
  const [settingsPassword, setSettingsPassword] = useState('')
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false)
  const [accessRequests, setAccessRequests] = useState([])
  const [accessRequestDocId, setAccessRequestDocId] = useState('')
  const [accessRequestPermission, setAccessRequestPermission] = useState('read')
  const [accessRequestReason, setAccessRequestReason] = useState('')
  const [approvalCodes, setApprovalCodes] = useState({})
  const [sessions, setSessions] = useState([])

  useEffect(() => {
    const token = localStorage.getItem('trustvault_token')
    if (token) api.get('/api/auth/me').then(r => { setUser(r.data); setTwoFactorEnabled(!!r.data.two_factor_enabled) }).catch(() => localStorage.removeItem('trustvault_token'))
  }, [])

  useEffect(() => {
    if (user || authMode !== 'login' || !googleClientId || !googleButtonRef.current) return
    let cancelled = false
    const initializeGoogle = () => {
      if (cancelled || !window.google?.accounts?.id || !googleButtonRef.current) return
      googleButtonRef.current.innerHTML = ''
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: async (response) => {
          if (!response?.credential) return
          setError(''); setNotice(''); setBusy(true)
          try {
            const { data } = await api.post('/api/auth/google', { credential: response.credential })
            if (data.requires_2fa) {
              setEmail(data.email); setAuthMode('otp'); setNotice(data.message || 'Enter the verification code sent to your email.')
            } else {
              acceptLogin(data)
            }
          } catch (e) {
            setError(errorMessage(e))
          } finally {
            setBusy(false)
          }
        },
        auto_select: false,
        context: 'signin',
      })
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        theme: 'outline', size: 'large', shape: 'rectangular',
        text: 'continue_with', logo_alignment: 'left', width: 340,
      })
    }
    const existingScript = document.querySelector('script[data-google-identity]')
    if (window.google?.accounts?.id) {
      initializeGoogle()
    } else if (existingScript) {
      existingScript.addEventListener('load', initializeGoogle, { once: true })
    } else {
      const script = document.createElement('script')
      script.src = 'https://accounts.google.com/gsi/client'
      script.async = true
      script.defer = true
      script.dataset.googleIdentity = 'true'
      script.onload = initializeGoogle
      script.onerror = () => { if (!cancelled) setError('Google sign-in could not load. Check your network or use email and password.') }
      document.head.appendChild(script)
    }
    return () => { cancelled = true; if (googleButtonRef.current) googleButtonRef.current.innerHTML = '' }
  }, [user, authMode, googleClientId])
  useEffect(() => { if (user) loadDocs() }, [user])
  useEffect(() => {
    if (!user) return
    if (page === 'audit' && user.role === 'admin') loadAudit()
    if (page === 'users' && user.role === 'admin') loadUsers()
    if (page === 'analytics') loadAnalytics()
    if (page === 'approvals' && user.role === 'admin') loadApprovals()
    if (page === 'accessRequests') loadAccessRequests()
    if (page === 'sessions') loadSessions()
    if (page === 'settings') setTwoFactorEnabled(!!user.two_factor_enabled)
  }, [page, user])

  async function run(action) {
    setError(''); setNotice(''); setBusy(true)
    try { await action() } catch (e) { setError(errorMessage(e)) }
    finally { setBusy(false) }
  }
  function acceptLogin(data) {
    localStorage.setItem('trustvault_token', data.access_token)
    setUser(data.user); setTwoFactorEnabled(!!data.user.two_factor_enabled); setAuthMode('login'); setOtp(''); setPage('documents'); setNotice('Welcome to TrustVault.')
  }
  async function login(e) {
    e.preventDefault()
    await run(async () => {
      const { data } = await api.post('/api/auth/login', { email, password })
      if (data.requires_2fa) { setAuthMode('otp'); setNotice('A verification code was sent to your email.'); return }
      acceptLogin(data)
    })
  }
  async function register(e) {
    e.preventDefault()
    await run(async () => {
      await api.post('/api/auth/register', { email, full_name: fullName, password })
      setAuthMode('login'); setPassword(''); setNotice('Account created. Sign in with your new email and password. New accounts start with Viewer access.')
    })
  }
  async function verifyOtp(e) {
    e.preventDefault()
    await run(async () => { const { data } = await api.post('/api/auth/2fa/verify', { email, code: otp }); acceptLogin(data) })
  }
  async function logout() {
    try { await api.post('/api/auth/logout') } catch { /* Always clear the local session, even if the API is offline. */ }
    localStorage.removeItem('trustvault_token'); setUser(null); setDocs([]); setSelected(null); setNotice(''); setError(''); setPassword(''); setOtp(''); setAuthMode('login')
  }
  async function loadDocs() {
    await run(async () => { const params = Object.fromEntries(Object.entries(filters).filter(([, v]) => v)); const { data } = await api.get('/api/documents', { params }); setDocs(data) })
  }
  async function uploadDoc(e) {
    e.preventDefault(); if (!file) { setError('Choose a file first.'); return }
    await run(async () => {
      const form = new FormData(); form.append('title', title || file.name); form.append('category', category); form.append('requires_approval', String(requiresApproval)); form.append('file', file)
      await api.post('/api/documents', form)
      setNotice(requiresApproval ? 'Document uploaded. Sharing is blocked until an administrator approves it.' : 'Document uploaded securely.')
      setTitle(''); setCategory('General'); setFile(null); setRequiresApproval(false); await loadDocs(); setPage('documents')
    })
  }
  async function openShare(doc) {
    setSelected(doc); setGrantEmail(''); setGrantExpiry('')
    await run(async () => { const { data } = await api.get(`/api/documents/${doc.id}/grants`); setGrants(data); setPage('share') })
  }
  async function addGrant(e) {
    e.preventDefault(); if (!selected) return
    await run(async () => {
      const payload = { email: grantEmail, permission: grantPermission }
      if (grantExpiry) payload.expires_at = new Date(grantExpiry).toISOString()
      await api.post(`/api/documents/${selected.id}/grants`, payload)
      setNotice('Access granted. Email notification is sent when SMTP is configured.'); const { data } = await api.get(`/api/documents/${selected.id}/grants`); setGrants(data)
    })
  }
  async function revokeGrant(userId) {
    if (!selected || !confirm('Revoke this person’s access immediately?')) return
    await run(async () => { await api.delete(`/api/documents/${selected.id}/grants/${userId}`); setNotice('Access revoked. Their next API request will be denied.'); const { data } = await api.get(`/api/documents/${selected.id}/grants`); setGrants(data) })
  }
  async function previewDoc(doc) {
    await run(async () => {
      const response = await api.get(`/api/documents/${doc.id}/preview`, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data)
      window.open(url, '_blank', 'noopener,noreferrer')
      setTimeout(() => URL.revokeObjectURL(url), 60000)
      setNotice('Preview authorized and recorded. Preview mode cannot prevent screenshots or browser-level saving.')
    })
  }
  async function downloadDoc(doc) {
    await run(async () => {
      const response = await api.get(`/api/documents/${doc.id}/download?watermark=true`, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data); const a = document.createElement('a'); a.href = url; const disposition = response.headers['content-disposition'] || ''; const match = disposition.match(/filename="([^"]+)"/i); a.download = match?.[1] || doc.original_filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url)
      setNotice('Integrity checked; personalized watermarked download authorized and recorded.')
    })
  }
  async function deleteDoc(doc) {
    if (!confirm(`Delete "${doc.title}" permanently?`)) return
    await run(async () => { await api.delete(`/api/documents/${doc.id}`); setNotice('Document deleted and recorded in the audit trail.'); await loadDocs() })
  }
  async function openVersions(doc) {
    setSelected(doc)
    await run(async () => { const { data } = await api.get(`/api/documents/${doc.id}/versions`); setVersions(data); setPage('versions') })
  }
  async function uploadVersion(e) {
    e.preventDefault(); if (!selected || !versionFile) return
    await run(async () => { const form = new FormData(); form.append('file', versionFile); form.append('note', versionNote); await api.post(`/api/documents/${selected.id}/versions`, form); setVersionFile(null); setVersionNote(''); const { data } = await api.get(`/api/documents/${selected.id}/versions`); setVersions(data); await loadDocs(); setNotice('New version saved; previous file remains in version history.') })
  }
  async function restoreVersion(version) {
    if (!selected || !confirm(`Restore version ${version.version_number}? The current version will be saved first.`)) return
    await run(async () => { await api.post(`/api/documents/${selected.id}/versions/${version.id}/restore`); const { data } = await api.get(`/api/documents/${selected.id}/versions`); setVersions(data); await loadDocs(); setNotice(`Version ${version.version_number} restored.`) })
  }
  async function checkIntegrity(doc) {
    await run(async () => { const { data } = await api.get(`/api/documents/${doc.id}/integrity`); setIntegrity(data); setNotice(data.valid ? 'File integrity verified.' : 'WARNING: file integrity check failed.') })
  }
  async function requestApproval(doc) {
    await run(async () => { await api.post(`/api/documents/${doc.id}/approval-request`, { note: 'Approval requested from document library' }); setNotice('Approval requested. Document sharing will be blocked until approved.'); await loadDocs() })
  }
  async function loadAudit() { await run(async () => { const params = Object.fromEntries(Object.entries(auditFilters).filter(([,v]) => v)); const { data } = await api.get('/api/audit', { params }); setAudit(data) }) }
  async function loadUsers() { await run(async () => { const { data } = await api.get('/api/users'); setUsers(data) }) }
  async function loadApprovals() { await run(async () => { const { data } = await api.get('/api/approvals'); setApprovals(data) }) }
  async function loadAnalytics() { await run(async () => { const { data } = await api.get('/api/analytics'); setAnalytics(data) }) }
  async function verifyAudit() { await run(async () => { const { data } = await api.get('/api/audit/verify'); setIntegrity(data); setNotice(data.valid ? 'Audit chain verified.' : 'Audit chain integrity failure detected.') }) }
  async function reviewApproval(item, status) {
    const reviewer_note = prompt(`Optional note for ${status} decision:`, '') || ''
    await run(async () => { await api.patch(`/api/approvals/${item.id}`, { status, reviewer_note }); setNotice(`Approval ${status}.`); await loadApprovals() })
  }
  async function updateUser(target, patch) {
    await run(async () => { await api.patch(`/api/users/${target.id}`, patch); setNotice('User account updated.'); await loadUsers() })
  }
  async function changeTwoFactor(e) {
    e.preventDefault()
    await run(async () => { const { data } = await api.patch('/api/auth/2fa', { enabled: !twoFactorEnabled, password: settingsPassword }); setTwoFactorEnabled(data.two_factor_enabled); setUser({ ...user, two_factor_enabled: data.two_factor_enabled }); setSettingsPassword(''); setNotice(data.two_factor_enabled ? 'Email-based two-factor authentication enabled.' : 'Two-factor authentication disabled.') })
  }

  async function loadAccessRequests() { await run(async () => { const { data } = await api.get('/api/access-requests'); setAccessRequests(data) }) }
  async function submitAccessRequest(e) {
    e.preventDefault()
    await run(async () => {
      await api.post(`/api/documents/${Number(accessRequestDocId)}/access-requests`, { permission: accessRequestPermission, reason: accessRequestReason })
      setAccessRequestDocId(''); setAccessRequestReason(''); setNotice('Access request sent to the document owner.'); await loadAccessRequests()
    })
  }
  async function beginAccessApproval(item) {
    await run(async () => { await api.post(`/api/access-requests/${item.id}/approve`); setNotice('Owner verification code sent to your registered email.'); await loadAccessRequests() })
  }
  async function verifyAccessApproval(item) {
    const code = approvalCodes[item.id] || ''
    await run(async () => { await api.post(`/api/access-requests/${item.id}/verify`, { code }); setNotice('OTP verified. Temporary access was granted for one hour.'); setApprovalCodes({...approvalCodes, [item.id]: ''}); await loadAccessRequests(); await loadDocs() })
  }
  async function denyAccessRequest(item) {
    if (!confirm('Deny this access request?')) return
    await run(async () => { await api.post(`/api/access-requests/${item.id}/deny`, { reason: 'Denied by document owner' }); setNotice('Access request denied and recorded.'); await loadAccessRequests() })
  }
  async function loadSessions() { await run(async () => { const { data } = await api.get('/api/sessions'); setSessions(data) }) }
  async function revokeSession(session) {
    if (!confirm(`Revoke session ${session.device_label}?`)) return
    await run(async () => { await api.delete(`/api/sessions/${session.id}`); setNotice('Session revoked. Its access token will no longer be accepted.'); await loadSessions() })
  }

  const nav = [
    { id: 'documents', label: 'Documents', icon: FolderOpen }, ...(user?.role === 'owner' || user?.role === 'admin' ? [{ id: 'upload', label: 'Upload file', icon: Upload }] : []),
    { id: 'analytics', label: 'Analytics', icon: BarChart3 }, { id: 'accessRequests', label: 'Access requests', icon: BellRing }, { id: 'sessions', label: 'Active sessions', icon: MonitorSmartphone }, { id: 'settings', label: 'Security settings', icon: Settings },
    ...(user?.role === 'admin' ? [{ id: 'approvals', label: 'Approvals', icon: ClipboardCheck }, { id: 'audit', label: 'Audit trail', icon: Activity }, { id: 'users', label: 'Users', icon: Users }] : []),
  ]

  if (!user) return <div className="login-shell">
    <div className="login-brand"><div className="brand-mark"><ShieldCheck size={27} /></div><div><h1>TrustVault</h1><p>Private documents. Accountable access.</p></div></div>
    <form className="login-card" onSubmit={authMode === 'register' ? register : authMode === 'otp' ? verifyOtp : login}>
      <div className="eyebrow">SECURE WORKSPACE</div>
      <h2>{authMode === 'register' ? 'Create your account' : authMode === 'otp' ? 'Verify your sign-in' : 'Welcome back'}</h2>
      <p className="muted">{authMode === 'register' ? 'Register with your own email and password.' : authMode === 'otp' ? `Enter the six-digit code sent to ${email}.` : 'Sign in to access authorized documents.'}</p>
      {notice && <div className="alert success"><CheckCircle2 size={17}/>{notice}</div>}{error && <div className="alert error"><AlertTriangle size={17}/>{error}</div>}
      {authMode === 'register' && <label>Full name<input value={fullName} onChange={e=>setFullName(e.target.value)} required minLength={2} maxLength={120} autoComplete="name" /></label>}
      <label>Email address<input type="email" value={email} onChange={e=>setEmail(e.target.value)} required autoComplete="email" /></label>
      {authMode !== 'otp' && <label>Password<div className="password-field"><input type={showPassword ? 'text' : 'password'} value={password} onChange={e=>setPassword(e.target.value)} required minLength={authMode === 'register' ? 12 : 1} maxLength={128} autoComplete={authMode === 'register' ? 'new-password' : 'current-password'} /><button type="button" className="password-toggle" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={()=>setShowPassword(value=>!value)}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></div>{authMode === 'register' && <small className="help">Use 12+ characters with uppercase, lowercase, and a number.</small>}</label>}
      {authMode === 'otp' && <label>6-digit verification code<input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={otp} onChange={e=>setOtp(e.target.value.replace(/\D/g, '').slice(0,6))} required /></label>}
      {authMode === 'login' && <div className="google-auth-area">
        <div className="auth-divider"><span>or continue with</span></div>
        {googleClientId
          ? <div className="google-button-wrap"><div ref={googleButtonRef} /></div>
          : <button type="button" className="google-config-button" onClick={() => setError('Google sign-in needs VITE_GOOGLE_CLIENT_ID in the Vercel/local frontend and GOOGLE_CLIENT_ID in the backend. See GOOGLE_SIGN_IN.md.')}>
              <span className="google-g" aria-hidden="true">G</span> Continue with Google
            </button>}
        {!googleClientId && <small className="help">Google sign-in becomes active after its client ID is configured.</small>}
      </div>}
      <button className="primary full" disabled={busy}>{busy ? 'Please wait…' : authMode === 'register' ? 'Create account' : authMode === 'otp' ? 'Verify and sign in' : 'Sign in securely'}</button>
      {authMode === 'otp' ? <button type="button" className="ghost" onClick={()=>{setAuthMode('login');setOtp('');setError('');setNotice('')}}>Back to sign in</button> : <button type="button" className="ghost" onClick={()=>{setAuthMode(authMode==='register'?'login':'register');setError('');setNotice('');setPassword('')}}>{authMode==='register'?'Already have an account? Sign in':'New to TrustVault? Create an account'}</button>}
      {authMode === 'register' && <div className="privacy-callout"><LockKeyhole size={17}/><span>New registrations receive the <b>Viewer</b> role. An administrator can promote a user when required; users cannot choose their own role.</span></div>}
    </form><p className="login-foot">Use your own account credentials. Never share passwords or verification codes.</p>
  </div>

  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark"><ShieldCheck size={24}/></div><div><strong>TrustVault</strong><small>SECURE WORKSPACE</small></div></div><div className="workspace-label">WORKSPACE</div>
      <nav>{nav.map(item => <button key={item.id} className={`nav-item ${page===item.id?'active':''}`} onClick={()=>{setPage(item.id);setSelected(null);setError('');setNotice('')}}><item.icon size={18}/>{item.label}</button>)}</nav>
      <div className="sidebar-bottom"><div className="secure-note"><LockKeyhole size={17}/><div><b>Protected access</b><span>Permissions checked by API</span></div></div><div className="profile"><div className="avatar">{user.full_name?.[0] || 'U'}</div><div className="profile-text"><b>{user.full_name}</b><span>{user.role}</span></div><button className="icon-button" title="Sign out" onClick={logout}><LogOut size={17}/></button></div></div>
    </aside>
    <main className="main"><header className="topbar"><div><span className="breadcrumb">TrustVault /</span> <strong>{nav.find(n=>n.id===page)?.label || (page==='share'?'Sharing & permissions':page==='versions'?'Version history':'Workspace')}</strong></div><div className="top-status"><span className="status-dot"></span> API-connected <span className="role-pill">{user.role}</span></div></header>
      <section className="content">
        {notice && <div className="alert success"><CheckCircle2 size={17}/>{notice}<button onClick={()=>setNotice('')} className="alert-close"><X size={15}/></button></div>}
        {error && <div className="alert error"><AlertTriangle size={17}/>{error}<button onClick={()=>setError('')} className="alert-close"><X size={15}/></button></div>}

        {page==='documents' && <>
          <div className="page-heading"><div><div className="eyebrow">DOCUMENT CONTROL</div><h1>Your document library</h1><p className="muted">Only documents you own or have been granted access to appear here.</p></div>{(user.role==='owner'||user.role==='admin')&&<button className="primary" onClick={()=>setPage('upload')}><Upload size={17}/> Upload document</button>}</div>
          <div className="stat-row"><div className="stat-card"><span>Visible documents</span><strong>{docs.length}</strong><small>Based on current access</small></div><div className="stat-card"><span>Your role</span><strong className="capitalize">{user.role}</strong><small>Enforced by the API</small></div><div className="stat-card"><span>File security</span><strong className="secure-text">Active</strong><small>Integrity checks enabled</small></div></div>
          <div className="panel filter-panel filter-wrap"><div className="search-field"><Search size={17}/><input placeholder="Search document title…" value={filters.search} onChange={e=>setFilters({...filters,search:e.target.value})} onKeyDown={e=>e.key==='Enter'&&loadDocs()}/></div><input placeholder="Category" value={filters.category} onChange={e=>setFilters({...filters,category:e.target.value})}/><input placeholder="Owner name" value={filters.owner} onChange={e=>setFilters({...filters,owner:e.target.value})}/><input placeholder="File type (pdf, txt)" value={filters.file_type} onChange={e=>setFilters({...filters,file_type:e.target.value})}/><input placeholder="SHA-256 prefix" value={filters.hash_prefix} onChange={e=>setFilters({...filters,hash_prefix:e.target.value})}/><input type="date" aria-label="Created from" value={filters.date_from} onChange={e=>setFilters({...filters,date_from:e.target.value})}/><input type="date" aria-label="Created to" value={filters.date_to} onChange={e=>setFilters({...filters,date_to:e.target.value})}/><select aria-label="Permission filter" value={filters.permission} onChange={e=>setFilters({...filters,permission:e.target.value})}><option value="">All permissions</option><option value="owner">Owner</option><option value="read">Read</option><option value="edit">Edit</option></select><select aria-label="Sort field" value={filters.sort_by} onChange={e=>setFilters({...filters,sort_by:e.target.value})}><option value="created_at">Created date</option><option value="updated_at">Updated date</option><option value="title">Title</option><option value="category">Category</option><option value="size">File size</option></select><select aria-label="Sort direction" value={filters.sort_order} onChange={e=>setFilters({...filters,sort_order:e.target.value})}><option value="desc">Descending</option><option value="asc">Ascending</option></select><button className="secondary" onClick={loadDocs}><Search size={16}/> Apply</button><button className="ghost" onClick={()=>{setFilters(initialFilters);setTimeout(()=>run(async()=>{const {data}=await api.get('/api/documents');setDocs(data)}),0)}}>Reset</button></div>
          <div className="section-title"><div><h2>Documents</h2><p className="muted">{docs.length} result(s)</p></div><button className="icon-text" onClick={loadDocs}><RefreshCw size={15}/> Refresh</button></div>
          <div className="document-grid">{docs.map(doc=><article className="document-card" key={doc.id}><div className="doc-card-top"><div className="file-icon"><FileText size={22}/></div><span className={`permission-badge ${doc.permission==='owner'?'owner':doc.permission==='edit'?'edit':''}`}>{doc.permission}</span></div><h3>{doc.title}</h3><p className="filename">{doc.original_filename}</p><div className="doc-meta"><span>{doc.category}</span><span>{formatBytes(doc.size_bytes)}</span></div><div className="doc-owner">Owner: {doc.owner_name}</div><div className="doc-hash" title={doc.sha256}>SHA-256 · {doc.sha256.slice(0,18)}…</div>{doc.requires_approval&&<div className={`approval-pill ${doc.approval_status}`}>Approval: {doc.approval_status}</div>}<div className="doc-actions"><button className="secondary" onClick={()=>previewDoc(doc)}><Eye size={15}/> Preview</button><button className="secondary" onClick={()=>downloadDoc(doc)}><Download size={15}/> Watermarked</button><button className="icon-button" title="Check integrity" onClick={()=>checkIntegrity(doc)}><Fingerprint size={16}/></button><button className="icon-button" title="Version history" onClick={()=>openVersions(doc)}><History size={16}/></button>{(doc.permission==='owner'||doc.permission==='share'||doc.permission==='download+share')&&<button className="icon-button" title="Manage permissions" onClick={()=>openShare(doc)}><Share2 size={16}/></button>}{doc.permission==='owner'&&<button className="icon-button danger-icon" title="Delete document" onClick={()=>deleteDoc(doc)}><Trash2 size={16}/></button>}</div>{doc.permission==='owner'&&!doc.requires_approval&&<button className="ghost full" onClick={()=>requestApproval(doc)}><ClipboardCheck size={14}/> Require approval before sharing</button>}</article>)}
          {!docs.length&&<div className="empty-state"><div className="empty-icon"><FolderOpen size={26}/></div><h3>No documents found</h3><p>Upload a file or adjust your search filters.</p>{(user.role==='owner'||user.role==='admin')&&<button className="primary" onClick={()=>setPage('upload')}><Upload size={16}/> Upload first document</button>}</div>}</div>
        </>}

        {page==='upload' && <div className="narrow-page"><div className="page-heading"><div><div className="eyebrow">PRIVATE STORAGE</div><h1>Upload a document</h1><p className="muted">Files are validated, hashed, and stored under generated private names.</p></div></div><form className="panel upload-panel" onSubmit={uploadDoc}><div className="upload-symbol"><Upload size={25}/></div><label>Document title<input value={title} onChange={e=>setTitle(e.target.value)} placeholder="e.g. Client agreement — Q4" maxLength={255}/></label><label>Category<select value={category} onChange={e=>setCategory(e.target.value)}><option>General</option><option>Contracts</option><option>Finance</option><option>Human Resources</option><option>Legal</option><option>Research</option><option>Operations</option></select></label><label>Choose file<input type="file" accept=".txt,.pdf,.png,.jpg,.jpeg" onChange={e=>setFile(e.target.files?.[0]||null)} required/><small className="help">Allowed: TXT, PDF, PNG, JPG, JPEG. Maximum 10 MB by default.</small></label>{file&&<div className="selected-file"><FileText size={19}/><div><b>{file.name}</b><small>{formatBytes(file.size)}</small></div><button type="button" className="icon-button" onClick={()=>setFile(null)}><X size={15}/></button></div>}<label className="check-label"><input type="checkbox" checked={requiresApproval} onChange={e=>setRequiresApproval(e.target.checked)}/> Require administrator approval before sharing</label><div className="privacy-callout"><LockKeyhole size={18}/><span><b>Private by default.</b> Sharing is server-authorized. PDF, image, and text downloads receive a personalized watermark.</span></div><button className="primary full" disabled={busy}>{busy?'Uploading…':'Upload securely'}</button></form></div>}

        {page==='share' && selected && <div className="narrow-page"><button className="back-link" onClick={()=>setPage('documents')}>← Back to documents</button><div className="page-heading"><div><div className="eyebrow">ACCESS MANAGEMENT</div><h1>Share permissions</h1><p className="muted">Manage access to <b>{selected.title}</b>.</p></div></div><form className="panel grant-form" onSubmit={addGrant}><h2>Grant access</h2><p className="muted">Only registered active users can be added. Expiry is optional.</p><label>Recipient email<input type="email" value={grantEmail} onChange={e=>setGrantEmail(e.target.value)} required placeholder="registered-user@example.com"/></label><label>Permission<select value={grantPermission} onChange={e=>setGrantPermission(e.target.value)}><option value="read">Read — metadata access, download denied</option><option value="edit">Edit — update document metadata and download</option><option value="download">Download only — file download permission</option><option value="share">Share — may grant access to others</option></select></label><label>Access expires (optional)<input type="datetime-local" value={grantExpiry} min={new Date(Date.now()+60000).toISOString().slice(0,16)} onChange={e=>setGrantExpiry(e.target.value)}/></label><button className="primary" disabled={busy}><Share2 size={16}/> Grant permission</button></form><div className="panel grants-panel"><h2>Active grants</h2>{grants.length===0&&<p className="muted">No one else currently has access.</p>}{grants.map(g=><div className="grant-row" key={g.user_id}><div className="avatar small">{g.full_name?.[0]}</div><div className="grant-person"><b>{g.full_name}</b><span>{g.email}</span><small>Expires: {g.expires_at?formatDate(g.expires_at):'Never'}</small></div><span className={`permission-badge ${g.permission==='edit'?'edit':''}`}>{g.permission}</span><button className="secondary revoke" onClick={()=>revokeGrant(g.user_id)}>Revoke</button></div>)}</div><div className="privacy-callout"><LockKeyhole size={18}/><span>Expired and revoked grants no longer authorize new requests. Already downloaded copies cannot be remotely recalled.</span></div></div>}

        {page==='versions' && selected && <div className="narrow-page"><button className="back-link" onClick={()=>setPage('documents')}>← Back to documents</button><div className="page-heading"><div><div className="eyebrow">DOCUMENT HISTORY</div><h1>Version history</h1><p className="muted">{selected.title} · current SHA-256 {selected.sha256?.slice(0,16)}…</p></div></div>{(selected.permission==='owner'||selected.permission==='edit')&&<form className="panel upload-panel" onSubmit={uploadVersion}><h2>Upload new version</h2><label>Replacement file<input type="file" accept=".txt,.pdf,.png,.jpg,.jpeg" onChange={e=>setVersionFile(e.target.files?.[0]||null)} required/></label><label>Change note<input value={versionNote} onChange={e=>setVersionNote(e.target.value)} maxLength={500} placeholder="What changed in this version?"/></label><button className="primary" disabled={busy}>Save new version</button></form>}<div className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>Version</th><th>File</th><th>Size</th><th>SHA-256</th><th>Created</th><th>Note</th><th>Action</th></tr></thead><tbody>{versions.map(v=><tr key={v.id}><td>v{v.version_number}</td><td>{v.original_filename}</td><td>{formatBytes(v.size_bytes)}</td><td><code title={v.sha256}>{v.sha256.slice(0,14)}…</code></td><td>{formatDate(v.created_at)}</td><td>{v.note}</td><td>{(selected.permission==='owner'||selected.permission==='edit')&&<button className="secondary" onClick={()=>restoreVersion(v)}>Restore</button>}</td></tr>)}</tbody></table></div>{!versions.length&&<p className="muted" style={{padding:20}}>No previous versions yet. Upload a new version to start a history.</p>}</div></div>}

        {page==='accessRequests' && <><div className="page-heading"><div><div className="eyebrow">OWNER-CONTROLLED ACCESS</div><h1>Access requests</h1><p className="muted">Request missing permissions or verify an owner's approval using a one-time email code.</p></div><button className="secondary" onClick={loadAccessRequests}><RefreshCw size={16}/> Refresh</button></div>
          <form className="panel upload-panel" onSubmit={submitAccessRequest}><div className="upload-symbol"><KeyRound size={24}/></div><h2>Request access to a document</h2><p className="muted">Enter the document ID provided by its owner. The request does not grant access until the owner approves it and verifies by email OTP.</p><label>Document ID<input type="number" min="1" value={accessRequestDocId} onChange={e=>setAccessRequestDocId(e.target.value)} required placeholder="e.g. 12"/></label><label>Requested permission<select value={accessRequestPermission} onChange={e=>setAccessRequestPermission(e.target.value)}><option value="read">Read</option><option value="edit">Edit</option><option value="download">Download</option><option value="share">Share with others</option></select></label><label>Reason<textarea value={accessRequestReason} onChange={e=>setAccessRequestReason(e.target.value)} rows={3} maxLength={1000} placeholder="Explain why you need access"/></label><button className="primary" disabled={busy}>Send access request</button></form>
          <div className="panel table-panel" style={{marginTop:18}}><div className="section-heading"><div><h2>Requests and decisions</h2><p className="muted">Owners see requests for their documents; requesters see their own requests.</p></div></div><div className="table-wrap"><table><thead><tr><th>Document</th><th>Requester</th><th>Permission</th><th>Reason</th><th>Status</th><th>Owner action</th></tr></thead><tbody>{accessRequests.map(item=><tr key={item.id}><td><b>{item.document_title}</b><small>Document #{item.document_id} · Request #{item.id}</small></td><td>{item.requester_email}</td><td>{item.requested_permission}</td><td>{item.reason||'—'}</td><td><span className={`outcome ${item.status==='approved'?'success':item.status==='denied'||item.status==='expired'?'denied':''}`}>{item.status}</span></td><td>{item.owner_id===user.id && item.status==='pending' && <div className="heading-actions"><button className="secondary" onClick={()=>beginAccessApproval(item)}>Approve with OTP</button><button className="secondary revoke" onClick={()=>denyAccessRequest(item)}>Deny</button></div>}{item.owner_id===user.id && item.status==='otp_pending' && <div className="heading-actions"><input aria-label="Owner OTP" placeholder="6-digit OTP" inputMode="numeric" maxLength={6} value={approvalCodes[item.id]||''} onChange={e=>setApprovalCodes({...approvalCodes,[item.id]:e.target.value.replace(/\D/g,'').slice(0,6)})}/><button className="primary" onClick={()=>verifyAccessApproval(item)}>Verify OTP</button><button className="secondary revoke" onClick={()=>denyAccessRequest(item)}>Deny</button></div>}</td></tr>)}</tbody></table></div>{!accessRequests.length&&<p className="muted" style={{padding:20}}>No access requests yet.</p>}</div></>}

        {page==='sessions' && <><div className="page-heading"><div><div className="eyebrow">IDENTITY & DEVICE SECURITY</div><h1>Active sessions</h1><p className="muted">Review sign-in devices and revoke sessions you don't recognize. Browser and IP information are risk signals, not proof of identity.</p></div><button className="secondary" onClick={loadSessions}><RefreshCw size={16}/> Refresh</button></div><div className="privacy-callout"><ShieldAlert size={18}/><span>Concurrent sign-ins create audit alerts and can email administrators when SMTP is configured. Enable email-based 2FA in Security settings to add a verification step at sign-in.</span></div><div className="panel table-panel" style={{marginTop:18}}><div className="table-wrap"><table><thead><tr><th>Device</th><th>IP address</th><th>Started</th><th>Last activity</th><th>Status</th><th>Action</th></tr></thead><tbody>{sessions.map(session=><tr key={session.id}><td><b>{session.device_label}</b><small>{session.user_agent||'Unknown browser'}</small></td><td>{session.ip_address||'Unknown'}</td><td>{formatDate(session.created_at)}</td><td>{formatDate(session.last_seen_at)}</td><td><span className={`outcome ${session.revoked_at?'denied':'success'}`}>{session.revoked_at?'revoked':'active'}</span></td><td>{!session.revoked_at&&<button className="secondary revoke" onClick={()=>revokeSession(session)}>Revoke</button>}</td></tr>)}</tbody></table></div>{!sessions.length&&<p className="muted" style={{padding:20}}>No session records found. Sign out and sign in again after updating the backend.</p>}</div></>}

        {page==='analytics' && <><div className="page-heading"><div><div className="eyebrow">WORKSPACE INSIGHTS</div><h1>Dashboard analytics</h1><p className="muted">Metrics are calculated by the backend based on your access scope.</p></div><button className="secondary" onClick={loadAnalytics}><RefreshCw size={16}/> Refresh</button></div><div className="stat-row"><Stat title="Visible documents" value={analytics?.document_count ?? '—'} note="Accessible to your account"/><Stat title="Owned documents" value={analytics?.owned_count ?? '—'} note="Documents you own"/><Stat title="Uploads (7 days)" value={analytics?.uploads_last_7_days ?? '—'} note="Recent activity"/></div><div className="stat-row"><Stat title="Successful downloads" value={analytics?.download_events ?? '—'} note="Your recorded download events"/><Stat title="Denied attempts" value={analytics?.denied_events ?? '—'} note="Security events in your scope"/>{user.role==='admin'&&<Stat title="Pending approvals" value={analytics?.pending_approvals ?? '—'} note="Waiting for review"/>}</div><div className="privacy-callout"><BarChart3 size={18}/><span>Analytics are informational. Do not treat them as a substitute for monitoring, alerting, or a protected audit backup.</span></div></>}

        {page==='settings' && <div className="narrow-page"><div className="page-heading"><div><div className="eyebrow">ACCOUNT SECURITY</div><h1>Security settings</h1><p className="muted">Enable an email verification step for future sign-ins.</p></div></div><form className="panel upload-panel" onSubmit={changeTwoFactor}><div className="upload-symbol"><ShieldAlert size={25}/></div><h2>Email-based two-factor authentication</h2><p className="muted">Current status: <b>{twoFactorEnabled?'Enabled':'Disabled'}</b></p><p className="muted">SMTP must be configured in the backend environment before enabling this feature.</p><label>Confirm current password<input type="password" value={settingsPassword} onChange={e=>setSettingsPassword(e.target.value)} required autoComplete="current-password"/></label><button className="primary" disabled={busy}>{twoFactorEnabled?'Disable 2FA':'Enable 2FA'}</button></form><div className="privacy-callout"><LockKeyhole size={18}/><span>Use a unique password. Production deployments should also consider verified email addresses, recovery codes, rate limiting, and a dedicated authentication provider.</span></div></div>}

        {page==='approvals' && user.role==='admin' && <><div className="page-heading"><div><div className="eyebrow">CONTROLLED SHARING</div><h1>Document approvals</h1><p className="muted">A pending or rejected document cannot be shared when approval is required.</p></div><button className="secondary" onClick={loadApprovals}><RefreshCw size={16}/> Refresh</button></div><div className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>Document</th><th>Requester</th><th>Requested</th><th>Note</th><th>Status</th><th>Decision</th></tr></thead><tbody>{approvals.map(item=><tr key={item.id}><td><b>{item.document_title}</b><small>Document #{item.document_id}</small></td><td>{item.requester_email}</td><td>{formatDate(item.created_at)}</td><td>{item.note||'—'}</td><td><span className={`outcome ${item.status==='approved'?'success':item.status==='rejected'?'denied':''}`}>{item.status}</span></td><td>{item.status==='pending'&&<div className="heading-actions"><button className="secondary" onClick={()=>reviewApproval(item,'approved')}>Approve</button><button className="secondary revoke" onClick={()=>reviewApproval(item,'rejected')}>Reject</button></div>}</td></tr>)}</tbody></table></div>{!approvals.length&&<p className="muted" style={{padding:20}}>No pending approval requests.</p>}</div></>}

        {page==='audit' && user.role==='admin' && <><div className="page-heading"><div><div className="eyebrow">ACCOUNTABILITY</div><h1>Audit trail</h1><p className="muted">Security-relevant actions, including denied access attempts and notification status.</p></div><div className="heading-actions"><button className="secondary" onClick={loadAudit}><RefreshCw size={16}/> Refresh</button><button className="primary" onClick={verifyAudit}><ShieldCheck size={16}/> Verify chain</button></div></div><div className="panel filter-panel"><input placeholder="Filter action name" value={auditFilters.action} onChange={e=>setAuditFilters({...auditFilters,action:e.target.value})}/><select value={auditFilters.outcome} onChange={e=>setAuditFilters({...auditFilters,outcome:e.target.value})}><option value="">All outcomes</option><option value="success">Success</option><option value="denied">Denied</option><option value="error">Error</option><option value="skipped_or_failed">Email skipped/failed</option></select><input type="number" min="1" placeholder="Actor user ID" value={auditFilters.actor_id} onChange={e=>setAuditFilters({...auditFilters,actor_id:e.target.value})}/><button className="secondary" onClick={loadAudit}><Search size={16}/> Filter events</button><button className="ghost" onClick={()=>{setAuditFilters({action:'',outcome:'',actor_id:''});setTimeout(()=>run(async()=>{const {data}=await api.get('/api/audit');setAudit(data)}),0)}}>Reset</button></div>{integrity&&<div className={`integrity-banner ${integrity.valid?'valid':'invalid'}`}><ShieldCheck size={22}/><div><b>{integrity.valid?'Audit chain verified':'Audit chain integrity failure'}</b><span>{integrity.checked} event(s) checked{integrity.failed_event_id?`, failure at event #${integrity.failed_event_id}`:''}. Hash chaining is tamper-evident, not independently immutable.</span></div></div>}<div className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>Event</th><th>Actor</th><th>Resource</th><th>Outcome</th><th>Time</th><th>Hash</th></tr></thead><tbody>{audit.map(e=><tr key={e.id}><td><b>{e.action}</b><small>#{e.id}</small></td><td>{e.actor_email||e.actor_id||'Anonymous'}</td><td>{e.resource_type} {e.resource_id||'—'}</td><td><span className={`outcome ${e.outcome}`}>{e.outcome}</span></td><td>{formatDate(e.created_at)}</td><td><code title={e.event_hash}>{e.event_hash.slice(0,12)}…</code></td></tr>)}</tbody></table></div>{!audit.length&&<div className="empty-state"><Activity size={25}/><p>No audit events yet.</p></div>}</div></>}

        {page==='users' && user.role==='admin' && <><div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1>User management</h1><p className="muted">Registration defaults to Viewer. Only administrators can change roles or deactivate accounts.</p></div><button className="secondary" onClick={loadUsers}><RefreshCw size={16}/> Refresh</button></div><div className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>2FA</th><th>Actions</th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td><b>{u.full_name}</b></td><td>{u.email}</td><td><select value={u.role} disabled={u.id===user.id} onChange={e=>updateUser(u,{role:e.target.value})}><option value="viewer">viewer</option><option value="owner">owner</option><option value="admin">admin</option></select></td><td><span className={`outcome ${u.is_active?'success':'denied'}`}>{u.is_active?'active':'inactive'}</span></td><td>{u.two_factor_enabled?'enabled':'off'}</td><td><button className="secondary" disabled={u.id===user.id} onClick={()=>updateUser(u,{is_active:!u.is_active})}>{u.is_active?'Deactivate':'Activate'}</button></td></tr>)}</tbody></table></div></div></>}
      </section><footer className="footer"><span>TrustVault · Secure document sharing</span><span><LockKeyhole size={13}/> Server-side authorization enabled</span></footer>
    </main>
  </div>
}

function Stat({title, value, note}) { return <div className="stat-card"><span>{title}</span><strong>{value}</strong><small>{note}</small></div> }
function formatBytes(bytes=0) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1024*1024) return `${(bytes/1024).toFixed(1)} KB`; return `${(bytes/1024/1024).toFixed(1)} MB` }
function formatDate(value) { if (!value) return '—'; return new Date(value).toLocaleString() }
