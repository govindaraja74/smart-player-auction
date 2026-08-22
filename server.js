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
const path = require('path'); // Added this to handle file routing

const app = express();
app.use(express.static(__dirname));
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ==========================================
// 2. MONGOOSE MODELS & SCHEMAS
// ==========================================

// 👇 REPLACE THIS STRING WITH YOUR ACTUAL MONGODB CONNECTION STRING 👇
const cloudDB = process.env.MONGO_URI || 'mongodb+srv://govindarajabhat_db_user:Adityaraja74@cluster0.qkovz4n.mongodb.net/SmartAuction?appName=Cluster0';
mongoose.connect(cloudDB)
    .then(() => console.log("✅ Successfully connected to MongoDB Atlas Cloud!"))
    .catch(err => console.error("❌ Cloud Database connection error:", err));

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

// ==========================================
// PERMANENT AUCTION HISTORY SCHEMA
// ==========================================
const SavedAuctionSchema = new mongoose.Schema({
    adminId: { type: String, default: "main_admin" },
    history: { type: Array, default: [] }
});
const SavedAuction = mongoose.model('SavedAuction', SavedAuctionSchema);
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
}, { strict: false });
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

    // ----------------------------------------------------
    // CLOUD SAVE & LOAD: AUCTION LIBRARY
    // ----------------------------------------------------
    
    // 1. Send saved auctions to the browser when the admin logs in
    socket.on('request_saved_auctions', async () => {
        try {
            let doc = await SavedAuction.findOne({ adminId: "main_admin" });
            if (doc && doc.history) {
                socket.emit('load_saved_auctions', doc.history);
            }
        } catch (err) {
            console.error('Error reading saved auctions from DB:', err);
        }
    });

    // 2. Save auction progress permanently to MongoDB when admin clicks save
    socket.on('save_auction_to_cloud', async (historyData) => {
        try {
            await SavedAuction.findOneAndUpdate(
                { adminId: "main_admin" },
                { history: historyData },
                { upsert: true, new: true } // "upsert" creates it if it doesn't exist yet
            );
            console.log('✅ Auction progress saved permanently to MongoDB.');
        } catch (err) {
            console.error('❌ Error saving auction to DB:', err);
        }
    });
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

// Route Handlers for the Frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/public.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public.html'));
});

app.get('/league.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'league.html'));
});

app.get('/franchise.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'franchise.html'));
});

app.get('/league-admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'league-admin.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
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

// Add a new Franchise
app.post('/api/franchises', async (req, res) => {
    try {
        const newFranchise = new Franchise({
            tournamentId: req.body.tournamentId || 'KBL2026',
            name: req.body.name,
            logoUrl: req.body.logoUrl,
            game: req.body.game,
            budget: req.body.budget,
            purseRemaining: req.body.purseRemaining
        });
        await newFranchise.save();
        res.json({ success: true });
    } catch (err) {
        console.error("Save Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// Edit a Franchise
app.put('/api/franchises/:id', async (req, res) => {
    try {
        await Franchise.findByIdAndUpdate(req.params.id, req.body);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete a Franchise
app.delete('/api/franchises/:id', async (req, res) => {
    try {
        await Franchise.findByIdAndDelete(req.params.id); 
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 7. START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Smart Players Auction server running on port ${PORT}`);
});
