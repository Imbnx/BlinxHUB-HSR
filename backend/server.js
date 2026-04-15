const express  = require('express')
const bcrypt   = require('bcryptjs')
const crypto   = require('crypto')
const fs       = require('fs')
const path     = require('path')
const cors     = require('cors')

const app = express()
app.use(cors())
app.use(express.json())

// ── DB ─────────────────────────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, 'users.db.json')

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')) }
  catch { return { users: [] } }
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2))
}

// ── Sessions (in-memory, 24h TTL) ─────────────────────────────────────────────
const sessions = new Map()

function makeToken(username, role) {
  const token = crypto.randomBytes(32).toString('hex')
  sessions.set(token, { username, role, expires: Date.now() + 86_400_000 })
  return token
}

function getSession(req) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim()
  const sess  = sessions.get(token)
  if (!sess || sess.expires < Date.now()) return null
  return sess
}

// ── Middleware ─────────────────────────────────────────────────────────────────
function requireOwner(req, res, next) {
  const sess = getSession(req)
  if (!sess || sess.role !== 'owner') return res.json({ ok: false, msg: 'Owner only.' })
  req.sess = sess
  next()
}

// ── Seed default owner ─────────────────────────────────────────────────────────
async function initOwner() {
  const db = loadDB()
  if (!db.users.find(u => u.role === 'owner')) {
    const username = process.env.OWNER_USERNAME || 'owner'
    const key      = process.env.OWNER_KEY      || 'BLINX-2024'
    db.users.push({
      username,
      keyHash: await bcrypt.hash(key, 10),
      role:    'owner',
      enabled: true,
      created: new Date().toISOString().split('T')[0]
    })
    saveDB(db)
    console.log(`[Auth] Default owner created  →  username: ${username}`)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Routes
// ══════════════════════════════════════════════════════════════════════════════

// Health check
app.get('/', (_, res) => res.json({ ok: true, service: 'BlinxHub API' }))

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, key } = req.body
  if (!username || !key) return res.json({ ok: false, msg: 'Username and key required.' })

  const db   = loadDB()
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase())

  if (!user)         return res.json({ ok: false, msg: 'User not found.' })
  if (!user.enabled) return res.json({ ok: false, msg: 'Account is disabled.' })

  const match = await bcrypt.compare(key, user.keyHash)
  if (!match) return res.json({ ok: false, msg: 'Invalid key.' })

  const token = makeToken(user.username, user.role)
  console.log('[Auth] Login:', user.username, '/', user.role)
  return res.json({ ok: true, token, username: user.username, role: user.role })
})

// GET /api/users
app.get('/api/users', requireOwner, (req, res) => {
  const db = loadDB()
  res.json({
    ok: true,
    users: db.users.map(u => ({
      username: u.username,
      role:     u.role,
      enabled:  u.enabled,
      created:  u.created
    }))
  })
})

// POST /api/users
app.post('/api/users', requireOwner, async (req, res) => {
  const { username, key, role = 'user' } = req.body
  if (!username || !key) return res.json({ ok: false, msg: 'Username and key required.' })

  const db = loadDB()
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.json({ ok: false, msg: 'Username already exists.' })

  db.users.push({
    username,
    keyHash: await bcrypt.hash(key, 10),
    role,
    enabled: true,
    created: new Date().toISOString().split('T')[0]
  })
  saveDB(db)
  console.log('[Owner] Created user:', username)
  res.json({ ok: true })
})

// PATCH /api/users/:username
app.patch('/api/users/:username', requireOwner, (req, res) => {
  const db   = loadDB()
  const user = db.users.find(u => u.username === req.params.username)
  if (!user) return res.json({ ok: false, msg: 'User not found.' })
  if (typeof req.body.enabled !== 'undefined') user.enabled = req.body.enabled
  saveDB(db)
  res.json({ ok: true })
})

// DELETE /api/users/:username
app.delete('/api/users/:username', requireOwner, (req, res) => {
  if (req.params.username === req.sess.username)
    return res.json({ ok: false, msg: 'Cannot delete yourself.' })
  const db = loadDB()
  db.users = db.users.filter(u => u.username !== req.params.username)
  saveDB(db)
  console.log('[Owner] Deleted user:', req.params.username)
  res.json({ ok: true })
})

// POST /api/users/:username/reset-key
app.post('/api/users/:username/reset-key', requireOwner, async (req, res) => {
  const { newKey } = req.body
  if (!newKey) return res.json({ ok: false, msg: 'New key required.' })

  const db   = loadDB()
  const user = db.users.find(u => u.username === req.params.username)
  if (!user) return res.json({ ok: false, msg: 'User not found.' })

  user.keyHash = await bcrypt.hash(newKey, 10)
  saveDB(db)
  console.log('[Owner] Key reset for:', req.params.username)
  res.json({ ok: true })
})

// POST /api/owner/credentials
app.post('/api/owner/credentials', requireOwner, async (req, res) => {
  const { newUsername, newKey } = req.body
  if (!newUsername && !newKey) return res.json({ ok: false, msg: 'Provide a username or key.' })

  const db   = loadDB()
  const user = db.users.find(u => u.username === req.sess.username)
  if (!user) return res.json({ ok: false, msg: 'Owner not found.' })

  if (newUsername) {
    const taken = db.users.find(u =>
      u.username.toLowerCase() === newUsername.toLowerCase() &&
      u.username !== req.sess.username
    )
    if (taken) return res.json({ ok: false, msg: 'Username already taken.' })

    // Update active session
    const token = req.headers.authorization.replace('Bearer ', '')
    const sess  = sessions.get(token)
    if (sess) sess.username = newUsername

    user.username = newUsername
  }

  if (newKey) user.keyHash = await bcrypt.hash(newKey, 10)

  saveDB(db)
  res.json({ ok: true, username: user.username })
})

// ── Start ──────────────────────────────────────────────────────────────────────
initOwner().then(() => {
  const PORT = process.env.PORT || 3000
  app.listen(PORT, () => console.log(`[BlinxHub API] Listening on port ${PORT}`))
})
