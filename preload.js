const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('hsr', {
  // ── HoYoLab ──
  getSession:      ()      => ipcRenderer.invoke('get-session'),
  doCheckIn:       ()      => ipcRenderer.invoke('do-checkin'),
  getCheckInInfo:  ()      => ipcRenderer.invoke('get-checkin-info'),
  openLogin:       ()      => ipcRenderer.send('open-login'),
  logout:          ()      => ipcRenderer.send('logout'),
  onLoginSuccess:  (cb)    => ipcRenderer.on('login-success', (_e, d) => cb(d)),
  onLoggedOut:     (cb)    => ipcRenderer.on('logged-out', () => cb()),

  // ── Local Auth ──
  localLogin:      (u, k)  => ipcRenderer.invoke('local-login', u, k),
  localLogout:     ()      => ipcRenderer.send('local-logout'),
  getLocalSession: ()      => ipcRenderer.invoke('get-local-session'),

  // ── Owner Panel ──
  listUsers:       ()      => ipcRenderer.invoke('list-users'),
  createUser:      (d)     => ipcRenderer.invoke('create-user', d),
  deleteUser:      (u)     => ipcRenderer.invoke('delete-user', u),
  updateUser:      (d)     => ipcRenderer.invoke('update-user', d),
  resetKey:        (d)     => ipcRenderer.invoke('reset-key', d),

  // ── Updates ──
  onForceUpdate:   (cb)    => ipcRenderer.on('force-update', (_e, d) => cb(d)),
  openExternal:    (url)   => ipcRenderer.invoke('open-external', url),
})