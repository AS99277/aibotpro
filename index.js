require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// --- DATABASE CONNECTION (Serverless Optimization) ---
let cachedDb = null;
async function connectToDatabase() {
    if (cachedDb) return cachedDb;
    const uri = process.env.MONGODB_URI;
    if (!uri) throw new Error('MONGODB_URI is not defined');
    const db = await mongoose.connect(uri);
    cachedDb = db;
    return db;
}

// --- MONGOOSE SCHEMAS ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, enum: ['active', 'suspended'], default: 'active' },
    wallet: {
        balance: { type: Number, default: 0 },
        totalDeposits: { type: Number, default: 0 },
        totalRewards: { type: Number, default: 0 }
    }
}, { timestamps: true });

const planSchema = new mongoose.Schema({
    name: { type: String, required: true },
    amount: { type: Number, required: true },
    dailyRate: { type: Number, required: true },
    illustrativeDaily: { type: Number, required: true },
    illustrativeThreshold: { type: Number, required: true },
    isActive: { type: Boolean, default: true }
});

const subscriptionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan' },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'active', 'completed'], default: 'pending' },
    dailyRewardsClaimed: { type: Number, default: 0 },
    lastClaimDate: { type: Date }
}, { timestamps: true });

const paymentVerificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan' },
    amount: { type: Number, required: true },
    utr: { type: String, required: true, unique: true },
    proofImage: { type: String }, // Base64
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
}, { timestamps: true });

const ledgerSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['deposit', 'reward', 'withdrawal', 'withdrawal_refund'] },
    amount: { type: Number, required: true },
    reference: { type: String },
    status: { type: String, default: 'completed' }
}, { timestamps: true });

const taskCompletionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    dateString: { type: String, required: true }, // e.g., 'YYYY-MM-DD'
    completedTasks: { type: Number, default: 0 }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: { type: Number, required: true },
    paymentMethod: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'paid'], default: 'pending' },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Plan = mongoose.models.Plan || mongoose.model('Plan', planSchema);
const Subscription = mongoose.models.Subscription || mongoose.model('Subscription', subscriptionSchema);
const PaymentVerification = mongoose.models.PaymentVerification || mongoose.model('PaymentVerification', paymentVerificationSchema);
const Ledger = mongoose.models.Ledger || mongoose.model('Ledger', ledgerSchema);
const TaskCompletion = mongoose.models.TaskCompletion || mongoose.model('TaskCompletion', taskCompletionSchema);
const Withdrawal = mongoose.models.Withdrawal || mongoose.model('Withdrawal', withdrawalSchema);

// --- INITIALIZATION (Seed Plans & Admin) ---
async function initDB() {
    await connectToDatabase();
    const plansCount = await Plan.countDocuments();
    if (plansCount === 0) {
        await Plan.insertMany([
            { name: 'Starter', amount: 500, dailyRate: 2, illustrativeDaily: 10, illustrativeThreshold: 1000 },
            { name: 'Silver', amount: 1000, dailyRate: 2, illustrativeDaily: 20, illustrativeThreshold: 2000 },
            { name: 'Gold', amount: 2000, dailyRate: 2, illustrativeDaily: 40, illustrativeThreshold: 4000 },
            { name: 'Platinum', amount: 4000, dailyRate: 2, illustrativeDaily: 80, illustrativeThreshold: 8000 },
            { name: 'Diamond', amount: 8000, dailyRate: 2, illustrativeDaily: 160, illustrativeThreshold: 16000 },
            { name: 'VIP', amount: 15000, dailyRate: 2, illustrativeDaily: 300, illustrativeThreshold: 30000 }
        ]);
    }
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@platform.com';
    const adminExists = await User.findOne({ email: adminEmail });
    if (!adminExists && process.env.ADMIN_PASSWORD_HASH) {
        await User.create({
            name: 'Administrator',
            phone: '0000000000',
            email: adminEmail,
            password: process.env.ADMIN_PASSWORD_HASH,
            role: 'admin'
        });
    }
}
initDB().catch(console.error);

// --- MIDDLEWARES ---
const authMiddleware = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Unauthorized' });
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// --- API ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, phone, email, password } = req.body;
        const exists = await User.findOne({ $or: [{ email }, { phone }] });
        if (exists) return res.status(400).json({ error: 'User already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ name, phone, email, password: hashedPassword });
        res.json({ message: 'Registration successful' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.status === 'suspended') return res.status(401).json({ error: 'Invalid credentials or suspended' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, role: user.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/user/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const activeSub = await Subscription.findOne({ user: user._id, status: 'active' }).populate('plan');
        const transactions = await Ledger.find({ user: user._id }).sort({ createdAt: -1 }).limit(10);
        res.json({ user, activePlan: activeSub?.plan || null, transactions });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/plans', async (req, res) => {
    const plans = await Plan.find({ isActive: true }).sort({ amount: 1 });
    res.json(plans);
});

app.post('/api/payment/request', authMiddleware, async (req, res) => {
    try {
        const { planId } = req.body;
        const plan = await Plan.findById(planId);
        if (!plan) return res.status(404).json({ error: 'Plan not found' });
        
        const upiId = process.env.UPI_ID || '6397319508@fam';
        const tn = `REQ${Date.now()}`;
        const upiUrl = `upi://pay?pa=${upiId}&pn=InvestmentPlatform&am=${plan.amount}&cu=INR&tn=${tn}`;
        const qrDataUrl = await qrcode.toDataURL(upiUrl);

        res.json({ qrDataUrl, upiId, amount: plan.amount, planName: plan.name, planId: plan._id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/payment/verify', authMiddleware, async (req, res) => {
    try {
        const { planId, utr, proofImage } = req.body;
        const plan = await Plan.findById(planId);
        const existing = await PaymentVerification.findOne({ utr });
        if (existing) return res.status(400).json({ error: 'UTR already submitted' });

        await PaymentVerification.create({
            user: req.user.id, plan: planId, amount: plan.amount, utr, proofImage
        });
        res.json({ message: 'Payment submitted for manual verification. Please wait for admin approval.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/tasks/complete', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const sub = await Subscription.findOne({ user: user._id, status: 'active' }).populate('plan');
        if (!sub) return res.status(400).json({ error: 'No active subscription' });
        
        const today = new Date().toISOString().split('T')[0];
        let taskRec = await TaskCompletion.findOne({ user: user._id, dateString: today });
        if (!taskRec) taskRec = await TaskCompletion.create({ user: user._id, dateString: today, completedTasks: 0 });
        
        if (taskRec.completedTasks >= 5) return res.status(400).json({ error: 'Daily tasks limit reached' });
        
        taskRec.completedTasks += 1;
        await taskRec.save();

        if (taskRec.completedTasks === 5) {
            // Reward calculation
            const reward = sub.plan.illustrativeDaily;
            user.wallet.balance += reward;
            user.wallet.totalRewards += reward;
            await user.save();
            await Ledger.create({ user: user._id, type: 'reward', amount: reward, reference: `Task Reward ${today}` });
            return res.json({ message: 'All tasks completed! Daily reward credited.', progress: 5, rewarded: true });
        }
        res.json({ message: `Task ${taskRec.completedTasks} completed.`, progress: taskRec.completedTasks, rewarded: false });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/withdraw/request', authMiddleware, async (req, res) => {
    try {
        const { amount, paymentMethod } = req.body;
        const user = await User.findById(req.user.id);
        if (user.wallet.balance < amount) return res.status(400).json({ error: 'Insufficient eligible balance' });
        
        user.wallet.balance -= amount; // Reserve funds
        await user.save();
        
        await Withdrawal.create({ user: user._id, amount, paymentMethod });
        await Ledger.create({ user: user._id, type: 'withdrawal', amount, reference: 'Pending Withdrawal' });
        
        res.json({ message: 'Withdrawal request submitted successfully.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Mount Admin Router
const adminRouter = require('./admin');
app.use('/admin', adminRouter);

// --- FRONTEND UI (Claymorphism Application) ---
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Investment Management Platform</title>
    <style>
        :root {
            --bg-grad: linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%);
            --clay-bg: rgba(255, 255, 255, 0.7);
            --clay-shadow: 8px 8px 16px rgba(142, 197, 252, 0.4), -8px -8px 16px rgba(255, 255, 255, 0.8);
            --clay-border: 2px solid rgba(255, 255, 255, 0.6);
            --primary: #705ec9; --text: #2d3748;
        }
        @media (prefers-reduced-motion: reduce) {
            * { animation: none !important; transition: none !important; }
        }
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background: var(--bg-grad); color: var(--text); min-height: 100vh; }
        nav { padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; background: var(--clay-bg); backdrop-filter: blur(10px); box-shadow: var(--clay-shadow); margin-bottom: 20px; }
        nav h1 { margin: 0; font-size: 24px; color: var(--primary); }
        .nav-links button { background: none; border: none; font-size: 16px; margin-left: 15px; cursor: pointer; font-weight: 600; color: var(--text); }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .clay-card { background: var(--clay-bg); backdrop-filter: blur(10px); border-radius: 24px; box-shadow: var(--clay-shadow); border: var(--clay-border); padding: 30px; margin-bottom: 20px; transition: transform 0.3s ease; }
        .clay-card:hover { transform: translateY(-5px); }
        
        .btn { background: var(--primary); color: white; border: none; padding: 12px 24px; border-radius: 16px; cursor: pointer; font-size: 16px; font-weight: bold; box-shadow: 4px 4px 10px rgba(112, 94, 201, 0.4), -4px -4px 10px rgba(255,255,255,0.6); transition: all 0.2s; }
        .btn:active { box-shadow: inset 4px 4px 10px rgba(0,0,0,0.2), inset -4px -4px 10px rgba(255,255,255,0.5); }
        
        input, select { width: 100%; padding: 12px; margin: 10px 0; border-radius: 12px; border: none; background: rgba(255,255,255,0.9); box-shadow: inset 3px 3px 6px rgba(0,0,0,0.1); outline: none; box-sizing: border-box; }
        
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .hidden { display: none !important; }
        .text-center { text-align: center; }
        
        .hero { text-align: center; padding: 60px 20px; }
        .hero h1 { font-size: 3rem; margin-bottom: 20px; color: var(--primary); }
        
        .disclaimer { font-size: 12px; color: #555; background: #fff3cd; padding: 10px; border-radius: 8px; margin-top: 10px; }
        .footer { text-align: center; padding: 20px; margin-top: 40px; font-size: 14px; background: var(--clay-bg); }
    </style>
</head>
<body>
    <nav>
        <h1>InvestPro</h1>
        <div class="nav-links" id="nav-links">
            <!-- Rendered by JS -->
        </div>
    </nav>
    <div class="container" id="app"></div>
    <div class="footer">
        Support: +91 9927766450 | WhatsApp: +91 7060969508 | Email: anmolsingh99277@gmail.com<br>
        UPI ID: 6397319508@fam<br>
        <small>Disclaimer: Proposed rewards depend on business funding. Not a guarantee of profit.</small>
    </div>

    <script>
        const API_URL = '/api';
        let currentUser = null;

        async function fetchAPI(endpoint, options = {}) {
            const token = localStorage.getItem('token');
            const headers = { 'Content-Type': 'application/json' };
            if (token) headers['Authorization'] = 'Bearer ' + token;
            const res = await fetch(API_URL + endpoint, { ...options, headers: { ...headers, ...options.headers } });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'API Error');
            return data;
        }

        function navigate(hash) {
            window.location.hash = hash;
            render();
        }

        function updateNav() {
            const nav = document.getElementById('nav-links');
            const token = localStorage.getItem('token');
            if (token) {
                nav.innerHTML = \`
                    <button onclick="navigate('#dashboard')">Dashboard</button>
                    <button onclick="navigate('#plans')">Plans</button>
                    <button onclick="navigate('#tasks')">Tasks</button>
                    <button onclick="navigate('#withdraw')">Withdraw</button>
                    <button onclick="logout()">Logout</button>
                \`;
            } else {
                nav.innerHTML = \`
                    <button onclick="navigate('#home')">Home</button>
                    <button onclick="navigate('#login')">Login</button>
                    <button onclick="navigate('#register')">Register</button>
                \`;
            }
        }

        function logout() {
            localStorage.removeItem('token');
            navigate('#home');
        }

        async function render() {
            updateNav();
            const app = document.getElementById('app');
            const hash = window.location.hash || '#home';
            app.innerHTML = '<div class="text-center">Loading...</div>';
            
            try {
                if (hash === '#home') renderHome(app);
                else if (hash === '#login') renderLogin(app);
                else if (hash === '#register') renderRegister(app);
                else if (hash === '#dashboard') await renderDashboard(app);
                else if (hash === '#plans') await renderPlans(app);
                else if (hash === '#tasks') renderTasks(app);
                else if (hash === '#withdraw') await renderWithdraw(app);
                else if (hash.startsWith('#payment')) await renderPayment(app, hash.split('=')[1]);
            } catch (err) {
                app.innerHTML = \`<div class="clay-card"><h2 style="color:red">Error</h2><p>\${err.message}</p><button class="btn" onclick="navigate('#home')">Go Back</button></div>\`;
            }
        }

        function renderHome(app) {
            app.innerHTML = \`
                <div class="hero">
                    <h1>Manage Your Investment Plans</h1>
                    <p>Experience a premium, secure, and intuitive platform to grow your rewards.</p>
                    <button class="btn" onclick="navigate('#register')">Create Account</button>
                    <button class="btn" onclick="navigate('#plans')">Explore Plans</button>
                </div>
                <div class="grid">
                    <div class="clay-card"><h3>1. Create Account</h3><p>Register securely and verify your details.</p></div>
                    <div class="clay-card"><h3>2. Choose a Plan</h3><p>Select from 6 flexible options.</p></div>
                    <div class="clay-card"><h3>3. Complete Tasks</h3><p>Engage daily to accumulate verified rewards.</p></div>
                </div>
            \`;
        }

        function renderLogin(app) {
            app.innerHTML = \`
                <div class="clay-card" style="max-width: 400px; margin: auto;">
                    <h2 class="text-center">Login</h2>
                    <form onsubmit="handleLogin(event)">
                        <input type="email" id="l-email" placeholder="Email Address" required>
                        <input type="password" id="l-password" placeholder="Password" required>
                        <button type="submit" class="btn" style="width: 100%">Login</button>
                    </form>
                </div>
            \`;
        }

        async function handleLogin(e) {
            e.preventDefault();
            try {
                const data = await fetchAPI('/auth/login', {
                    method: 'POST',
                    body: JSON.stringify({ email: document.getElementById('l-email').value, password: document.getElementById('l-password').value })
                });
                localStorage.setItem('token', data.token);
                if (data.role === 'admin') window.location.href = '/admin';
                else navigate('#dashboard');
            } catch (err) { alert(err.message); }
        }

        function renderRegister(app) {
            app.innerHTML = \`
                <div class="clay-card" style="max-width: 400px; margin: auto;">
                    <h2 class="text-center">Register</h2>
                    <form onsubmit="handleRegister(event)">
                        <input type="text" id="r-name" placeholder="Full Name" required>
                        <input type="text" id="r-phone" placeholder="Mobile Number" required>
                        <input type="email" id="r-email" placeholder="Email Address" required>
                        <input type="password" id="r-password" placeholder="Password" required>
                        <div class="disclaimer"><input type="checkbox" required> I accept the Terms & Conditions.</div>
                        <button type="submit" class="btn" style="width: 100%; margin-top: 15px;">Register</button>
                    </form>
                </div>
            \`;
        }

        async function handleRegister(e) {
            e.preventDefault();
            try {
                await fetchAPI('/auth/register', {
                    method: 'POST',
                    body: JSON.stringify({ 
                        name: document.getElementById('r-name').value, phone: document.getElementById('r-phone').value,
                        email: document.getElementById('r-email').value, password: document.getElementById('r-password').value 
                    })
                });
                alert('Registration successful! Please login.');
                navigate('#login');
            } catch (err) { alert(err.message); }
        }

        async function renderDashboard(app) {
            const data = await fetchAPI('/user/dashboard');
            currentUser = data.user;
            
            let txHtml = data.transactions.map(t => \`<p>\${t.type.toUpperCase()}: ₹\${t.amount} (\${new Date(t.createdAt).toLocaleDateString()}) - \${t.status}</p>\`).join('');
            
            app.innerHTML = \`
                <h2 style="color:var(--primary)">Welcome, \${data.user.name}</h2>
                <div class="grid">
                    <div class="clay-card">
                        <h3>Wallet Balance</h3>
                        <h1>₹\${data.user.wallet.balance}</h1>
                        <p>Total Deposits: ₹\${data.user.wallet.totalDeposits}</p>
                        <p>Total Rewards: ₹\${data.user.wallet.totalRewards}</p>
                    </div>
                    <div class="clay-card">
                        <h3>Active Plan</h3>
                        \${data.activePlan ? \`
                            <h2>\${data.activePlan.name}</h2>
                            <p>Daily Proposed Reward: ₹\${data.activePlan.illustrativeDaily}</p>
                            <button class="btn" onclick="navigate('#tasks')">Go to Daily Tasks</button>
                        \` : \`
                            <p>No active plan found.</p>
                            <button class="btn" onclick="navigate('#plans')">Browse Plans</button>
                        \`}
                    </div>
                </div>
                <div class="clay-card" style="margin-top: 20px;">
                    <h3>Recent Transactions</h3>
                    \${txHtml || '<p>No transactions yet.</p>'}
                </div>
            \`;
        }

        async function renderPlans(app) {
            const plans = await fetchAPI('/plans');
            let html = '<h2 class="text-center">Select an Investment Plan</h2><div class="grid">';
            plans.forEach(p => {
                html += \`
                    <div class="clay-card text-center">
                        <h2>\${p.name}</h2>
                        <h1>₹\${p.amount}</h1>
                        <p>Proposed Daily: \${p.dailyRate}% (₹\${p.illustrativeDaily})</p>
                        <p>Illustrative Threshold: ₹\${p.illustrativeThreshold}</p>
                        <button class="btn" onclick="requestPayment('\${p._id}')">Select Plan</button>
                        <div class="disclaimer">Amounts are proposed configuration values, not guaranteed profits.</div>
                    </div>
                \`;
            });
            html += '</div>';
            app.innerHTML = html;
        }

        async function requestPayment(planId) {
            if(!localStorage.getItem('token')) return navigate('#login');
            try {
                const data = await fetchAPI('/payment/request', { method: 'POST', body: JSON.stringify({ planId }) });
                sessionStorage.setItem('paymentData', JSON.stringify(data));
                navigate('#payment=' + planId);
            } catch (err) { alert(err.message); }
        }

        async function renderPayment(app, planId) {
            const pData = JSON.parse(sessionStorage.getItem('paymentData'));
            if(!pData) return navigate('#plans');
            
            app.innerHTML = \`
                <div class="clay-card" style="max-width: 500px; margin: auto; text-align:center;">
                    <h2>Complete Payment</h2>
                    <p>Plan: <strong>\${pData.planName}</strong> | Amount: <strong>₹\${pData.amount}</strong></p>
                    <img src="\${pData.qrDataUrl}" alt="UPI QR Code" style="width: 250px; border-radius: 16px; margin: 10px 0;">
                    <p>UPI ID: <strong>\${pData.upiId}</strong> <button class="btn" style="padding: 5px 10px; font-size:12px;" onclick="navigator.clipboard.writeText('\${pData.upiId}')">Copy</button></p>
                    <div style="text-align:left; margin-top:20px;">
                        <label>Enter UTR / Reference Number (Required)</label>
                        <input type="text" id="utr" placeholder="12-digit UTR" required>
                        <button class="btn" style="width:100%; margin-top:15px;" onclick="submitPaymentProof('\${planId}')">Submit for Verification</button>
                    </div>
                    <p class="disclaimer">Payment activation disabled until verified by admin. A screenshot is not proof of successful settlement.</p>
                </div>
            \`;
        }

        async function submitPaymentProof(planId) {
            const utr = document.getElementById('utr').value;
            if(!utr) return alert('UTR is required');
            try {
                await fetchAPI('/payment/verify', { method: 'POST', body: JSON.stringify({ planId, utr }) });
                alert('Payment proof submitted successfully! Waiting for manual verification.');
                navigate('#dashboard');
            } catch (err) { alert(err.message); }
        }

        function renderTasks(app) {
            app.innerHTML = \`
                <div class="clay-card" style="max-width: 600px; margin: auto; text-align:center;">
                    <h2>Daily Educational Tasks</h2>
                    <p>Complete 5 tasks to unlock today's reward.</p>
                    <div id="task-progress" style="margin:20px 0; font-size: 24px; font-weight: bold; color: var(--primary);">Progress: 0 / 5</div>
                    <button class="btn" onclick="completeTask()">Complete Next Task</button>
                    <div class="disclaimer" style="margin-top: 20px;">Rewards are based on verified, eligible activity and legitimate funding.</div>
                </div>
            \`;
        }

        async function completeTask() {
            try {
                const data = await fetchAPI('/tasks/complete', { method: 'POST' });
                document.getElementById('task-progress').innerText = \`Progress: \${data.progress} / 5\`;
                alert(data.message);
                if(data.rewarded) navigate('#dashboard');
            } catch (err) { alert(err.message); }
        }

        async function renderWithdraw(app) {
            app.innerHTML = \`
                <div class="clay-card" style="max-width: 500px; margin: auto;">
                    <h2 class="text-center">Withdraw Funds</h2>
                    <p class="text-center">Eligible Balance: Loading...</p>
                    <form onsubmit="handleWithdraw(event)">
                        <input type="number" id="w-amount" placeholder="Amount to withdraw" required min="100">
                        <input type="text" id="w-method" placeholder="Bank Account or UPI ID" required>
                        <button type="submit" class="btn" style="width: 100%">Submit Request</button>
                    </form>
                    <div class="disclaimer">Withdrawals are subject to authorized approval and eligibility rules. Not guaranteed.</div>
                </div>
            \`;
            try {
                const data = await fetchAPI('/user/dashboard');
                document.querySelector('.clay-card p').innerText = \`Eligible Balance: ₹\${data.user.wallet.balance}\`;
            } catch (e) {}
        }

        async function handleWithdraw(e) {
            e.preventDefault();
            try {
                await fetchAPI('/withdraw/request', {
                    method: 'POST',
                    body: JSON.stringify({ amount: document.getElementById('w-amount').value, paymentMethod: document.getElementById('w-method').value })
                });
                alert('Withdrawal request submitted successfully.');
                navigate('#dashboard');
            } catch (err) { alert(err.message); }
        }

        window.addEventListener('hashchange', render);
        window.addEventListener('load', render);
    </script>
</body>
</html>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;
