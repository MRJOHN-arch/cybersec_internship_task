const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const fs = require('fs');

const app = express();
const db = new sqlite3.Database(':memory:');
const SECRET_KEY = "internship_super_secret_key_12345";

// --- API SECURITY HARDENING ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "TOO_MANY_REQUESTS" }
});

const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 login attempts per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "TOO_MANY_LOGIN_ATTEMPTS" }
});

// Restrict CORS to localhost only
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/login-', loginLimiter);

// --- LOGGING (Fail2Ban style) ---
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} ${level}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: 'security.log' }),
        new winston.transports.Console()
    ],
});

// --- SECURITY HEADERS (Helmet + CSP + HSTS) ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            upgradeInsecureRequests: null,
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// FIXED: This was causing the rate-limit error
// Changed from true → false because we're running directly on localhost (no proxy)
app.set('trust proxy', false);

// --- DATABASE SETUP ---
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)");
    const hash = bcrypt.hashSync("password123", 10);
    db.run("INSERT INTO users (email, password) VALUES (?, ?)", ["admin@example.com", hash]);
});

// --- GUI (unchanged structure, safe string concatenation) ---
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>CyberShield Intern Portal</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-slate-950 text-white min-h-screen p-8">
            <div class="max-w-5xl mx-auto">
                <header class="border-b border-slate-800 pb-6 mb-8 flex justify-between items-center">
                    <div>
                        <h1 class="text-3xl font-black text-blue-500 tracking-tight">🛡️ CYBERSHIELD V2</h1>
                        <p class="text-slate-500 text-xs font-mono uppercase tracking-widest">Fail2Ban / SQLi / Auth Laboratory</p>
                    </div>
                    <div class="flex items-center gap-2 bg-green-500/10 text-green-500 px-3 py-1 rounded-full border border-green-500/20 text-xs font-bold">
                        <span class="relative flex h-2 w-2">
                          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                          <span class="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                        </span>
                        CORE SYSTEM ACTIVE
                    </div>
                </header>
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-10">
                    <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 shadow-2xl">
                        <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
                            <span class="p-2 bg-blue-500/20 rounded-lg text-blue-400">01</span>
                            Authentication Control
                        </h2>
                        <div class="space-y-5">
                            <div>
                                <label class="block text-[10px] font-black text-slate-500 uppercase mb-2">Target Identity</label>
                                <input id="email" type="email" value="admin@example.com" class="w-full bg-slate-950 border border-slate-800 p-4 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition font-mono">
                            </div>
                            <div>
                                <label class="block text-[10px] font-black text-slate-500 uppercase mb-2">Access Key</label>
                                <input id="password" type="password" placeholder="ENTER PASSWORD" class="w-full bg-slate-950 border border-slate-800 p-4 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition font-mono">
                            </div>
                            <div class="grid grid-cols-1 gap-3 pt-4">
                                <button onclick="handleLogin('secure')" class="bg-blue-600 hover:bg-blue-700 p-4 rounded-xl font-black uppercase tracking-tighter transition">
                                    Secure Verification (W4)
                                </button>
                                <button onclick="handleLogin('vulnerable')" class="border-2 border-red-900/50 text-red-500 hover:bg-red-500/5 p-4 rounded-xl font-black uppercase tracking-tighter transition text-sm">
                                    Execute SQLi Injection (W5)
                                </button>
                            </div>
                        </div>
                        <div id="auth-status" class="mt-8 p-4 rounded-xl bg-black font-mono text-xs border border-slate-800 hidden"></div>
                    </div>
                    <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 shadow-2xl">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-lg font-bold text-orange-500 flex items-center gap-2">
                                <span class="p-2 bg-orange-500/20 rounded-lg text-orange-400">02</span>
                                Threat Intelligence Log
                            </h2>
                            <button onclick="updateLogs()" class="text-[10px] font-bold text-slate-500 hover:text-white uppercase tracking-widest">Force Refresh</button>
                        </div>
                        <div id="log-display" class="bg-black p-5 rounded-2xl h-[340px] overflow-y-auto font-mono text-[10px] text-green-500 border border-slate-800 space-y-1 leading-relaxed">
                            <div class="text-slate-700 underline">// KERNEL READY. WATCHING LOGS...</div>
                        </div>
                    </div>
                </div>
            </div>
            <script>
                async function handleLogin(route) {
                    const email = document.getElementById('email').value;
                    const password = document.getElementById('password').value;
                    const status = document.getElementById('auth-status');
                   
                    status.classList.remove('hidden');
                    status.className = "mt-8 p-4 rounded-xl bg-black font-mono text-xs border border-blue-500/30 text-blue-400";
                    status.innerHTML = '<span class="animate-pulse">_ EXEC_AUTH_REQUEST...</span>';
                    try {
                        const response = await fetch('/api/login-' + route, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email, password })
                        });
                       
                        const data = await response.json();
                        if (response.ok) {
                            status.className = "mt-8 p-4 rounded-xl bg-green-500/10 font-mono text-xs border border-green-500/30 text-green-400";
                            status.innerText = "SUCCESS: AUTH_TOKEN_GENERATED";
                        } else {
                            status.className = "mt-8 p-4 rounded-xl bg-red-500/10 font-mono text-xs border border-red-500/30 text-red-500";
                            status.innerText = "DENIED: " + (data.error || "INVALID_CREDS");
                        }
                    } catch (err) {
                        status.className = "mt-8 p-4 rounded-xl bg-red-950 text-white font-mono text-xs border-2 border-red-600";
                        status.innerText = "FATAL ERROR: BANNED. CONNECTION REFUSED BY FAIL2BAN.";
                    }
                    updateLogs();
                }

                async function updateLogs() {
                    try {
                        const res = await fetch('/api/raw-logs');
                        const logs = await res.json();
                        const display = document.getElementById('log-display');
                        if (logs.length > 0) {
                            display.innerHTML = logs.map(l => '<div><span class="text-slate-600">[' + l.time + ']</span> ' + l.msg + '</div>').join('');
                            display.scrollTop = display.scrollHeight;
                        }
                    } catch (e) {}
                }
               
                setInterval(updateLogs, 4000);
                window.onload = updateLogs;
            </script>
        </body>
        </html>
    `);
});

// --- API ENDPOINTS ---
app.post('/api/login-secure', (req, res) => {
    const { email, password } = req.body;
    const clientIp = req.ip === '::1' ? '127.0.0.1' : req.ip;

    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ error: "MALFORMED_INPUT" });
    }

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
            logger.info(`Successful login: ${email}`);
            res.json({ success: true, token });
        } else {
            logger.error(`FAILED LOGIN attempt for admin from IP ${clientIp}`);
            res.status(401).json({ error: "ACCESS_DENIED" });
        }
    });
});

app.post('/api/login-vulnerable', (req, res) => {
    const { email, password } = req.body;
    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
   
    db.get(query, (err, row) => {
        if (row) {
            logger.warn(`SECURITY_ALERT: SQLi Bypass on ${email}`);
            res.json({ bypass: true });
        } else {
            res.status(401).json({ error: "SQL_QUERY_EMPTY" });
        }
    });
});

app.get('/api/raw-logs', (req, res) => {
    if (!fs.existsSync('security.log')) return res.json([]);
    const content = fs.readFileSync('security.log', 'utf8')
        .split('\n')
        .filter(l => l)
        .slice(-25)
        .map(l => {
            const parts = l.split(' ');
            const time = parts[0] + ' ' + (parts[1] || '---');
            const msg = l.includes('error:') ? l.split('error:')[1].trim() :
                       l.includes('info:') ? l.split('info:')[1].trim() :
                       l.includes('warn:') ? l.split('warn:')[1].trim() : l;
            return { time, msg };
        });
    res.json(content);
});

app.listen(3000, () => {
    console.log("🚀 V2 Server Online at http://localhost:3000");
});
