// ==========================================
// 1. IMPORTS & SERVER SETUP
// ==========================================
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ==========================================
// 2. MONGOOSE MODELS & SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/SmartAuction')
    .then(() => console.log("✅ Connected to MongoDB"))
    .catch(err => console.error("❌ Database error:", err));

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});
UserSchema.methods.comparePassword = async function(cand) { return bcrypt.compare(cand, this.password); };
const User = mongoose.model('User', UserSchema);

const TournamentSchema = new mongoose.Schema({
    ownerId: { type: String, required: true },
    name: { type: String, required: true },
    roomCode: { type: String, required: true, unique: true },
    budgetPerTeam: { type: Number, required: true },
    isUnlocked: { type: Boolean, default: false },
    venueIpAddress: { type: String, default: null },
    umpirePins: [{ type: String }]
});
const Tournament = mongoose.model('Tournament', TournamentSchema);

const PlayerSchema = new mongoose.Schema({
    tournamentId: { type: String, required: true },
    name: { type: String, required: true },
    category: { type: String, required: true },
    basePrice: { type: Number, required: true },
    status: { type: String, default: 'pending' },
    soldToTeamId: { type: String, default: null },
    soldPrice: { type: Number, default: 0 }
});
const Player = mongoose.model('Player', PlayerSchema);

const FranchiseSchema = new mongoose.Schema({
    tournamentId: { type: String, required: true },
    ownerId: { type: String }, 
    name: { type: String, required: true },
    purseRemaining: { type: Number, required: true },
    logoUrl: { type: String },
    game: { type: String },
    budget: { type: Number },
    loginPin: { type: String },
    roster: [{ name: String, category: String, price: Number }]
});
const Franchise = mongoose.model('Franchise', FranchiseSchema);

const MatchSchema = new mongoose.Schema({
    tournamentId: { type: String, required: true },
    teamA_Id: { type: String, required: true },
    teamB_Id: { type: String, required: true },
    teamA_Lineup: [{ type: String }],
    teamB_Lineup: [{ type: String }],
    currentScore: {
        teamA: { sets: { type: Number, default: 0 }, points: { type: Number, default: 0 } },
        teamB: { sets: { type: Number, default: 0 }, points: { type: Number, default: 0 } }
    },
    status: { type: String, default: 'scheduled' },
    winningTeamId: { type: String, default: null },
    endCondition: { type: String, default: 'normal' }
});
const Match = mongoose.model('Match', MatchSchema);

// ==========================================
// 3. MIDDLEWARE (Auth & Security)
// ==========================================
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        next();
    } catch (err) { res.status(403).json({ message: 'Invalid token' }); }
};

const venueLockMiddleware = async (req, res, next) => {
    try {
        const tournamentId = req.body.tournamentId || req.user.tournamentId;
        const tournament = await Tournament.findById(tournamentId);
        if (!tournament.venueIpAddress) return next();
        
        let userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (userIp && userIp.includes(',')) userIp = userIp.split(',')[0].trim();
        
        if (userIp !== tournament.venueIpAddress) {
            return res.status(403).json({ message: 'SECURITY BLOCK: Must be on Venue Wi-Fi.' });
        }
        next();
    } catch (err) { res.status(500).json({ message: 'IP check error' }); }
};

// ==========================================
// 4. REST API ROUTES
// ==========================================

// Super Admin Unlock (Manual Payment Override)
app.post('/api/superadmin/unlock', async (req, res) => {
    if (req.body.masterPassword !== process.env.SUPER_ADMIN_PASSWORD) return res.status(401).send('Denied');
    await Tournament.findByIdAndUpdate(req.body.tournamentId, { isUnlocked: true });
    res.json({ message: 'Unlocked successfully' });
});

// Organizer Auth
app.post('/api/auth/register', async (req, res) => {
    try {
        const user = new User(req.body);
        await user.save();
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret');
        res.json({ token });
    } catch (err) { res.status(500).send('Error'); }
});

// Admin WiFi Lock
app.post('/api/tournaments/lock-wifi', authMiddleware, async (req, res) => {
    let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (clientIp && clientIp.includes(',')) clientIp = clientIp.split(',')[0].trim();
    await Tournament.findOneAndUpdate({ _id: req.body.tournamentId, ownerId: req.user.userId }, { venueIpAddress: clientIp });
    res.json({ lockedIp: clientIp });
});

// Public Player Registration
app.post('/api/public/register/:roomCode', async (req, res) => {
    const tourney = await Tournament.findOne({ roomCode: req.params.roomCode });
    if (!tourney) return res.status(404).send('Invalid Code');
    const player = new Player({ tournamentId: tourney._id, name: req.body.name, category: req.body.category, basePrice: req.body.basePrice });
    await player.save();
    res.json({ message: 'Registered' });
});

// Venue Login (Umpires & Owners)
app.post('/api/venue/login', venueLockMiddleware, async (req, res) => {
    const { roomCode, pin, role } = req.body;
    const tourney = await Tournament.findOne({ roomCode });
    if (!tourney) return res.status(404).send('Not found');

    let payload;
    if (role === 'owner') {
        const team = await Franchise.findOne({ tournamentId: tourney._id, loginPin: pin });
        if (!team) return res.status(401).send('Invalid PIN');
        payload = { role, teamId: team._id, tournamentId: tourney._id };
    } else {
        if (!tourney.umpirePins.includes(pin)) return res.status(401).send('Invalid PIN');
        payload = { role, tournamentId: tourney._id };
    }
    const token = jwt.sign(payload, process.env.JWT_SECRET || 'secret', { expiresIn: '12h' });
    res.json({ token, role });
});

// ==========================================
// 5. SOCKET.IO (Real-Time Engine)
// ==========================================
io.on('connection', (socket) => {
    socket.on('joinRoom', (roomCode) => { socket.join(roomCode); socket.roomCode = roomCode; });

    // Live Auction - Sell Player
    socket.on('adminSellPlayer', async (data) => {
        const session = await mongoose.startSession();
        session.startTransaction();
        try {
            const { playerId, teamId, soldPrice, tournamentId } = data;
            const tourney = await Tournament.findById(tournamentId).session(session);
            
            // Freemium Demo Check
            if (!tourney.isUnlocked) {
                const soldCount = await Player.countDocuments({ tournamentId, status: 'sold' }).session(session);
                if (soldCount >= 5) throw new Error('DEMO_LIMIT');
            }

            const team = await Franchise.findById(teamId).session(session);
            const player = await Player.findById(playerId).session(session);
            
            team.purseRemaining -= soldPrice;
            team.roster.push({ name: player.name, category: player.category, price: soldPrice });
            player.status = 'sold'; player.soldToTeamId = team._id; player.soldPrice = soldPrice;
            
            await team.save({ session });
            await player.save({ session });
            await session.commitTransaction();
            
            io.to(socket.roomCode).emit('alert', `${player.name} SOLD!`);
        } catch (err) {
            await session.abortTransaction();
            socket.emit('bidError', err.message === 'DEMO_LIMIT' ? 'Demo Limit Reached' : 'Sale Failed');
        } finally { session.endSession(); }
    });

    // Umpire - Score Update
    socket.on('umpireUpdateScore', async (data) => {
        io.to(socket.roomCode).emit('liveScoreUpdate', data);
        Match.findByIdAndUpdate(data.matchId, { 'currentScore.teamA': data.teamA, 'currentScore.teamB': data.teamB, status: 'live' }).exec();
    });

    // Umpire - End Match
    socket.on('umpireEndMatch', async (data) => {
        const { matchId, winner, condition } = data;
        const match = await Match.findById(matchId);
        if(!match) return;
        const winningTeamId = winner === 'A' ? match.teamA_Id : match.teamB_Id;
        match.status = 'completed'; match.winningTeamId = winningTeamId; match.endCondition = condition;
        await match.save();
        io.to(socket.roomCode).emit('matchConcluded', { matchId, reason: condition });
    });
});

// ==========================================
// 6. FRONTEND HTML STRINGS & ROUTES
// ==========================================

// SEO-Optimized Homepage UI
const HTML_HOME = `
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Primary Meta Tags -->
    <title>Smart Players Auction | Sports League Management Software</title>
    <meta name="title" content="Smart Players Auction | Sports League Management Software">
    <meta name="description" content="The ultimate digital platform for running live sports auctions, digital scoreboards, and league management. Perfect for badminton, cricket, and local sports tournaments.">
    <meta name="keywords" content="sports auction software, badminton league management, player draft app, live sports bidding, digital umpire scoreboard, tournament manager India">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Open Graph / WhatsApp / Facebook -->
    <meta property="og:type" content="website">
    <meta property="og:title" content="Smart Players Auction | Live Draft & Scoring">
    <meta property="og:description" content="Run professional live sports auctions and digital umpire scoreboards straight from your phone.">
    <meta property="og:site_name" content="Smart Players Auction">

    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f3f4f6; color: #1f2937; margin: 0; padding: 0; text-align: center; }
        .hero { background: #1e3a8a; color: white; padding: 4rem 2rem; }
        .hero h1 { font-size: 2.5rem; margin-bottom: 1rem; }
        .hero p { font-size: 1.2rem; color: #d1d5db; max-width: 600px; margin: 0 auto 2rem auto; line-height: 1.5; }
        .features { display: flex; flex-wrap: wrap; justify-content: center; gap: 2rem; padding: 3rem 1rem; }
        .feature-card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 300px; }
        .btn { display: inline-block; background: #10b981; color: white; padding: 1rem 2rem; text-decoration: none; font-size: 1.2rem; font-weight: bold; border-radius: 8px; transition: background 0.3s; cursor: pointer; border: none; }
        .btn:hover { background: #059669; }
    </style>
</head>
<body>
    <div class="hero">
        <h1>Smart Players Auction</h1>
        <p>The complete digital operating system for your sports league. From live franchise bidding to real-time courtside scoreboards.</p>
       <button onclick="window.location.href='/admin'" style="background-color: #28a745; color: white; padding: 12px 24px; border: none; border-radius: 8px; font-size: 18px; cursor: pointer; font-weight: bold;">
  Organizer Login
</button>
    </div>
    
    <div class="features">
        <div class="feature-card">
            <h3 style="color: #2563eb;">Live Bidding Room</h3>
            <p>Run your franchise player draft smoothly. Connects owners in real-time via local Wi-Fi.</p>
        </div>
        <div class="feature-card">
            <h3 style="color: #10b981;">Digital Scoreboards</h3>
            <p>BWF-compliant umpire tablets that broadcast live scores directly to the spectator screen.</p>
        </div>
        <div class="feature-card">
            <h3 style="color: #f59e0b;">League Standings</h3>
            <p>Automatically track points, walkovers, and team rosters all in one secure place.</p>
        </div>
    </div>
</body>
</html>
`;

// Player Registration UI
const HTML_REGISTER = `
<!DOCTYPE html><html><head><title>Smart Players Auction - Registration</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>
body{font-family:sans-serif; background:#f3f4f6; padding:2rem;} .card{background:#fff; padding:2rem; max-width:400px; margin:auto; border-radius:8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);} input,select,button{width:100%; padding:10px; margin:10px 0; border-radius:4px; border:1px solid #d1d5db; box-sizing: border-box;} button{background:#2563eb; color:white; border:none; cursor:pointer; font-weight: bold;} .title{text-align: center; color: #1e3a8a; margin-bottom: 0;} .subtitle{text-align: center; color: #6b7280; margin-top: 5px; margin-bottom: 20px;}
</style></head><body>
<div class="card">
    <h2 class="title">Smart Players Auction</h2>
    <p class="subtitle">Player Registration</p>
    <form id="regForm">
        <input type="text" id="name" placeholder="Full Name" required>
        <select id="category"><option>Smash Specialist</option><option>Defender</option><option>All-Rounder</option></select>
        <input type="number" id="price" placeholder="Base Price (₹)" required>
        <button type="submit">Submit Registration</button>
    </form>
</div>
<script>
    const code = new URLSearchParams(window.location.search).get('room');
    document.getElementById('regForm').onsubmit = async(e) => {
        e.preventDefault();
        const res = await fetch('/api/public/register/' + code, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name: document.getElementById('name').value, category: document.getElementById('category').value, basePrice: document.getElementById('price').value }) });
        alert(res.ok ? "Successfully Registered for the Draft!" : "Error registering. Please try again.");
    }
</script></body></html>`;

// Umpire Scoreboard UI
const HTML_UMPIRE = `
<!DOCTYPE html><html><head><title>Smart Players Auction - Umpire</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>
body{background:#111827; color:white; font-family:sans-serif; margin:0; padding:10px;} .header{text-align:center; padding: 10px; color: #9ca3af;} .grid{display:grid; grid-template-columns:1fr 1fr; gap:10px;} .btn{padding:2rem; font-size:2rem; width:100%; background:#10b981; border:none; color:white; border-radius:8px; cursor: pointer;} .team-panel{background:#1f2937; padding: 1rem; border-radius: 8px; text-align: center;}
</style></head><body>
    <div class="header">
        <h3>Smart Players Auction<br><small>Umpire Control Board</small></h3>
    </div>
    <div class="grid">
        <div class="team-panel"><h3>Team A</h3><h1 id="scoreA">0</h1><button class="btn" onclick="add('A')">+1</button></div>
        <div class="team-panel"><h3>Team B</h3><h1 id="scoreB">0</h1><button class="btn" onclick="add('B')">+1</button></div>
    </div>
<script src="/socket.io/socket.io.js"></script><script>
    const socket = io(); socket.emit('joinRoom', 'DEFAULT-ROOM');
    let state = { matchId: '123', teamA:{score:0, sets:0}, teamB:{score:0, sets:0} };
    function add(t) { t==='A'?state.teamA.score++:state.teamB.score++; document.getElementById('score'+t).innerText = state['team'+t].score; socket.emit('umpireUpdateScore', state); }
</script></body></html>`;

// Route Handlers for the Frontend
app.get('/', (req, res) => res.send(HTML_HOME));
app.get('/register', (req, res) => res.send(HTML_REGISTER));
app.get('/umpire', (req, res) => res.send(HTML_UMPIRE));
app.get('/admin', (req, res) => {
    res.sendFile(__dirname + '/admin.html');
});

// ==========================================
// Admin Data Fetch
app.get('/api/dashboard', async (req, res) => {
    const players = await Player.find({ status: 'pending' });
    const teams = await Franchise.find();
    res.json({ players, teams });
});

// Create New Team
app.post('/api/teams', async (req, res) => {
    const team = new Franchise({ 
        tournamentId: 'KBL2026', 
        name: req.body.name, 
        purseRemaining: req.body.budget 
    });
    await team.save();
    res.json({ success: true });
});

// Save Smart Player Form Config & Categories
app.post('/api/players/register', async (req, res) => {
    const player = new Player({ 
        tournamentId: req.body.tournamentId || 'KBL2026', 
        name: req.body.name, 
        category: req.body.category, 
        game: req.body.game,
        basePrice: req.body.basePrice,
        status: 'pending'
    });
    await player.save();
    res.json({ success: true });
});
// Edit a Franchise
app.put('/api/franchises/:id', async (req, res) => {
    try {
        await Team.findByIdAndUpdate(req.params.id, req.body);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete a Franchise
app.delete('/api/franchises/:id', async (req, res) => {
    try {
        await Team.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// 7. START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Smart Players Auction server running on port ${PORT}`);
});
