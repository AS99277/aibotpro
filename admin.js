const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const router = express.Router();

// --- ADMIN AUTH MIDDLEWARE ---
const adminMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Unauthorized' });
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: 'Forbidden: Admins only' });
        req.admin = decoded;
        next();
    } catch (err) { res.status(401).json({ error: 'Invalid token' }); }
};

// --- ADMIN API ROUTES ---
router.get('/api/stats', adminMiddleware, async (req, res) => {
    const User = mongoose.model('User');
    const PaymentVerification = mongoose.model('PaymentVerification');
    const Withdrawal = mongoose.model('Withdrawal');
    
    const usersCount = await User.countDocuments({ role: 'user' });
    const pendingPayments = await PaymentVerification.find({ status: 'pending' }).populate('user').populate('plan');
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' }).populate('user');
    
    res.json({ usersCount, pendingPayments, pendingWithdrawals });
});

router.post('/api/payments/:id/verify', adminMiddleware, async (req, res) => {
    try {
        const { action } = req.body; // 'approve' or 'reject'
        const PaymentVerification = mongoose.model('PaymentVerification');
        const Subscription = mongoose.model('Subscription');
        const User = mongoose.model('User');
        const Ledger = mongoose.model('Ledger');

        const payment = await PaymentVerification.findById(req.params.id);
        if (!payment || payment.status !== 'pending') return res.status(400).json({ error: 'Invalid payment record' });

        if (action === 'approve') {
            payment.status = 'verified';
            // Activate plan
            await Subscription.create({ user: payment.user, plan: payment.plan, amount: payment.amount, status: 'active' });
            // Update User deposits
            const user = await User.findById(payment.user);
            user.wallet.totalDeposits += payment.amount;
            await user.save();
            await Ledger.create({ user: payment.user, type: 'deposit', amount: payment.amount, reference: `Verified UTR: ${payment.utr}` });
        } else {
            payment.status = 'rejected';
        }
        await payment.save();
        res.json({ message: `Payment ${action}d successfully` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/api/withdrawals/:id/verify', adminMiddleware, async (req, res) => {
    try {
        const { action } = req.body; // 'approve' or 'reject'
        const Withdrawal = mongoose.model('Withdrawal');
        const User = mongoose.model('User');
        const Ledger = mongoose.model('Ledger');

        const withdrawal = await Withdrawal.findById(req.params.id);
        if (!withdrawal || withdrawal.status !== 'pending') return res.status(400).json({ error: 'Invalid withdrawal record' });

        if (action === 'approve') {
            withdrawal.status = 'paid';
            // Funds were already reserved in balance deduction.
        } else {
            withdrawal.status = 'rejected';
            // Refund the balance
            const user = await User.findById(withdrawal.user);
            user.wallet.balance += withdrawal.amount;
            await user.save();
            await Ledger.create({ user: withdrawal.user, type: 'withdrawal_refund', amount: withdrawal.amount, reference: 'Withdrawal Rejected Refund' });
        }
        await withdrawal.save();
        res.json({ message: `Withdrawal ${action}d successfully` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ADMIN FRONTEND UI ---
router.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Investment Platform</title>
    <style>
        :root { --bg: #1a202c; --card: #2d3748; --text: #e2e8f0; --accent: #4fd1c5; }
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .card { background: var(--card); padding: 20px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #4a5568; }
        button { background: var(--accent); color: #1a202c; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        button.danger { background: #fc8181; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container" id="admin-app">Loading Admin Panel...</div>
    <script>
        const API_URL = '/admin/api';
        
        async function fetchAdmin(endpoint, options = {}) {
            const token = localStorage.getItem('token');
            if(!token) { window.location.href = '/#login'; return; }
            const res = await fetch(API_URL + endpoint, { 
                ...options, 
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token } 
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            return data;
        }

        async function renderAdmin() {
            try {
                const data = await fetchAdmin('/stats');
                
                let paymentsHtml = data.pendingPayments.map(p => \`
                    <tr>
                        <td>\${p.user.email}</td>
                        <td>\${p.plan.name} (₹\${p.amount})</td>
                        <td>\${p.utr}</td>
                        <td>
                            <button onclick="verifyPayment('\${p._id}', 'approve')">Approve</button>
                            <button class="danger" onclick="verifyPayment('\${p._id}', 'reject')">Reject</button>
                        </td>
                    </tr>
                \`).join('') || '<tr><td colspan="4">No pending payments.</td></tr>';

                let withdrawalsHtml = data.pendingWithdrawals.map(w => \`
                    <tr>
                        <td>\${w.user.email}</td>
                        <td>₹\${w.amount}</td>
                        <td>\${w.paymentMethod}</td>
                        <td>
                            <button onclick="verifyWithdrawal('\${w._id}', 'approve')">Mark Paid</button>
                            <button class="danger" onclick="verifyWithdrawal('\${w._id}', 'reject')">Reject</button>
                        </td>
                    </tr>
                \`).join('') || '<tr><td colspan="4">No pending withdrawals.</td></tr>';

                document.getElementById('admin-app').innerHTML = \`
                    <header>
                        <h2>Admin Control Panel</h2>
                        <div>
                            <span>Total Users: \${data.usersCount}</span>
                            <button onclick="localStorage.removeItem('token'); window.location.href='/'" style="margin-left:20px;">Logout</button>
                        </div>
                    </header>
                    <div class="card">
                        <h3>Pending Payment Verifications</h3>
                        <table>
                            <tr><th>User</th><th>Plan</th><th>UTR Reference</th><th>Actions</th></tr>
                            \${paymentsHtml}
                        </table>
                    </div>
                    <div class="card">
                        <h3>Pending Withdrawals</h3>
                        <table>
                            <tr><th>User</th><th>Amount</th><th>Method</th><th>Actions</th></tr>
                            \${withdrawalsHtml}
                        </table>
                    </div>
                \`;
            } catch (err) {
                document.getElementById('admin-app').innerHTML = \`<h2 style="color:red">Access Denied: \${err.message}</h2>\`;
            }
        }

        async function verifyPayment(id, action) {
            if(!confirm(\`Are you sure you want to \${action} this payment?\`)) return;
            try {
                await fetchAdmin(\`/payments/\${id}/verify\`, { method: 'POST', body: JSON.stringify({ action }) });
                renderAdmin();
            } catch(e) { alert(e.message); }
        }

        async function verifyWithdrawal(id, action) {
            if(!confirm(\`Are you sure you want to \${action} this withdrawal?\`)) return;
            try {
                await fetchAdmin(\`/withdrawals/\${id}/verify\`, { method: 'POST', body: JSON.stringify({ action }) });
                renderAdmin();
            } catch(e) { alert(e.message); }
        }

        window.onload = renderAdmin;
    </script>
</body>
</html>
    `);
});

module.exports = router;
