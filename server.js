// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

app.use(express.json());
app.use(cookieParser());

// CORS config (supports multiple origins in CLIENT_URL env var)
const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:3000')
  .split(',')
  .map(o => o.trim());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true
}));

// Socket.IO setup with same CORS list
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  }
});

/* ----------------------------- MONGODB ----------------------------- */

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI || process.env.MONGODB_URI;
    if (!mongoURI) throw new Error('MONGO_URI or MONGODB_URI is not defined');

    const options = {
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 2,
      family: 4,
      retryWrites: true,
      retryReads: true,
    };

    const conn = await mongoose.connect(mongoURI, options);
    console.log(`MongoDB connected: ${conn.connection.host}/${conn.connection.name}`);

    // Ensure sparse unique email index
    try {
      const colls = await mongoose.connection.db.listCollections({ name: 'users' }).toArray();
      if (colls.length > 0) {
        const idxs = await mongoose.connection.db.collection('users').indexes();
        const emailIdx = idxs.find(i => i.key && i.key.email === 1);
        if (!emailIdx || (emailIdx && !emailIdx.sparse)) {
          try {
            if (emailIdx && emailIdx.name) {
              await mongoose.connection.db.collection('users').dropIndex(emailIdx.name);
            }
          } catch (e) {}
          await mongoose.connection.db.collection('users').createIndex(
            { email: 1 },
            { unique: true, sparse: true, name: 'email_1' }
          );
          console.log('Sparse email index ensured.');
        }
      }
    } catch (indexError) {
      console.warn('Index check error (non-fatal):', indexError.message);
    }
  } catch (err) {
    console.error('DB connection failed:', err.message);
    if (process.env.NODE_ENV === 'production') {
      setTimeout(connectDB, 10000);
    } else {
      process.exit(1);
    }
  }
};

connectDB();

/* ----------------------------- SCHEMAS ----------------------------- */

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 2, maxlength: 30 },
  email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  password: { type: String, minlength: 6 },
  gender: { type: String, required: true, enum: ['male','female','other','trans','prefer-not-to-say'] },
  isAnonymous: { type: Boolean, default: false },
  tokenVersion: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  if (this.isAnonymous && !this.password) return next();
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
messageSchema.index({ sender: 1, receiver: 1, createdAt: 1 });
const Message = mongoose.model('Message', messageSchema);

/* ----------------------------- AUTH ----------------------------- */

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

const generateToken = (userId, tokenVersion) => {
  return jwt.sign({ userId, tokenVersion }, JWT_SECRET, { expiresIn: '7d' });
};

const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided.' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return res.status(401).json({ message: 'User not found.' });
    if (user.tokenVersion === undefined || user.tokenVersion === null) {
      user.tokenVersion = 0;
      await user.save();
    }
    if (decoded.tokenVersion === undefined) return res.status(401).json({ message: 'Old token format.' });
    if (decoded.tokenVersion !== user.tokenVersion) return res.status(401).json({ message: 'Session invalidated.' });
    req.userId = decoded.userId;
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expired.' });
    if (err.name === 'JsonWebTokenError') return res.status(403).json({ message: 'Invalid token.' });
    res.status(500).json({ message: 'Authentication error.' });
  }
};

/* ----------------------------- SOCKET AUTH MIDDLEWARE ----------------------------- */

// Maps for tracking users and sessions
const onlineUsers = new Map(); // userId -> socketId
const activeCalls = new Map(); // roomId -> { participants: [userId], callType, initiator }
const waitingUsers = new Map(); // userId -> socketId for random chat
const activeRandomChats = new Map(); // userId -> matchedUserId
const randomChatSessions = new Map(); // sessionId -> { participants, createdAt }

io.use((socket, next) => {
  try {
    // Accept token in handshake auth or authorization header
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');
    if (!token) return next();
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded && decoded.userId) {
      socket.userId = decoded.userId;
      console.log(`Socket authenticated for user ${socket.userId} (socket ${socket.id})`);
    }
    return next();
  } catch (err) {
    console.warn('Socket auth failed:', err.message);
    // Allow connection to continue (so anonymous/guest flows still work). To disallow: next(new Error('Authentication error'));
    return next();
  }
});

/* ----------------------------- SOCKET.IO EVENTS ----------------------------- */

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // Auto-register if socket.userId already present from handshake token
  if (socket.userId) {
    onlineUsers.set(socket.userId, socket.id);
    console.log(`Auto-registered user ${socket.userId} -> socket ${socket.id}`);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  }

  // explicit registration (backwards-compatible)
  socket.on('register', (userId) => {
    if (!userId) return;
    socket.userId = userId;
    onlineUsers.set(userId, socket.id);
    console.log(`User registered: ${userId} -> socket ${socket.id}`);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  });

  /* ---------- Messaging ---------- */
  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, text, tempId } = data;
      const message = new Message({ sender: senderId, receiver: receiverId, text });
      await message.save();
      const populatedMessage = await message.populate([{ path: 'sender', select: 'username email' }, { path: 'receiver', select: 'username email' }]);
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) io.to(receiverSocketId).emit('receiveMessage', populatedMessage);
      socket.emit('messageSent', { tempId, message: populatedMessage });
    } catch (err) {
      console.error('sendMessage error:', err.message);
      socket.emit('messageError', { message: 'Failed to send message' });
    }
  });

  socket.on('typing', ({ senderId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) io.to(receiverSocketId).emit('userTyping', { userId: senderId });
  });

  socket.on('stopTyping', ({ senderId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) io.to(receiverSocketId).emit('userStoppedTyping', { userId: senderId });
  });

  /* ----------------------------- RANDOM CHAT EVENTS ----------------------------- */
  
  // Check if random chat is available
  socket.on('check-random-chat-availability', () => {
    const availableUsers = Array.from(waitingUsers.keys()).filter(id => 
      id !== socket.userId && !activeRandomChats.has(id)
    );
    const isAvailable = availableUsers.length > 0 || waitingUsers.size > 0;
    socket.emit('random-chat-available', isAvailable);
  });

  // Start looking for random chat
  socket.on('start-random-chat', async (data) => {
    try {
      const { userId, username } = data;
      
      if (!userId) {
        socket.emit('random-chat-error', { message: 'User ID required' });
        return;
      }

      console.log(`User ${userId} started random chat search`);
      
      // Add user to waiting pool
      waitingUsers.set(userId, socket.id);
      socket.emit('random-chat-waiting');
      
      // Find a random match (excluding self and already matched users)
      const availableUsers = Array.from(waitingUsers.keys()).filter(id => 
        id !== userId && 
        !activeRandomChats.has(id)
      );
      
      if (availableUsers.length > 0) {
        // Pick a random user
        const randomIndex = Math.floor(Math.random() * availableUsers.length);
        const matchedUserId = availableUsers[randomIndex];
        
        // Get matched user details from database
        const matchedUser = await User.findById(matchedUserId).select('username email _id gender');
        
        if (matchedUser) {
          // Create chat session
          const sessionId = `random-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
          
          activeRandomChats.set(userId, matchedUserId);
          activeRandomChats.set(matchedUserId, userId);
          randomChatSessions.set(sessionId, {
            participants: [userId, matchedUserId],
            createdAt: new Date()
          });
          
          // Remove both from waiting
          waitingUsers.delete(userId);
          waitingUsers.delete(matchedUserId);
          
          // Get current user details for the matched user
          const currentUser = await User.findById(userId).select('username email _id gender');
          
          // Notify both users
          socket.emit('random-match-found', matchedUser);
          
          const matchedUserSocketId = onlineUsers.get(matchedUserId);
          if (matchedUserSocketId) {
            io.to(matchedUserSocketId).emit('random-match-found', currentUser);
          }
          
          console.log(`Random match created: ${userId} <-> ${matchedUserId}`);
          
        } else {
          waitingUsers.delete(userId);
          socket.emit('random-chat-error', { message: 'Match user not found' });
        }
      } else {
        // No users available, keep waiting
        console.log(`User ${userId} waiting for random match (${waitingUsers.size} users waiting)`);
        socket.emit('random-chat-waiting', { waitingCount: waitingUsers.size });
      }
      
    } catch (error) {
      console.error('Error in start-random-chat:', error);
      if (data.userId) waitingUsers.delete(data.userId);
      socket.emit('random-chat-error', { message: 'Failed to find match' });
    }
  });

  // Stop random chat
  socket.on('stop-random-chat', (data) => {
    const { userId } = data;
    
    console.log(`User ${userId} stopped random chat`);
    
    // Remove from waiting
    waitingUsers.delete(userId);
    
    // If in active chat, notify partner and end chat
    const partnerId = activeRandomChats.get(userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) {
        io.to(partnerSocketId).emit('random-match-left');
      }
      activeRandomChats.delete(partnerId);
      activeRandomChats.delete(userId);
      
      // Clean up session
      for (const [sessionId, session] of randomChatSessions.entries()) {
        if (session.participants.includes(userId)) {
          randomChatSessions.delete(sessionId);
          break;
        }
      }
    }
    
    socket.emit('random-chat-stopped');
  });

  // Send message in random chat
  socket.on('send-random-message', async (data) => {
    try {
      const { senderId, receiverId, text, tempId } = data;
      
      // Verify this is a valid random chat pair
      if (activeRandomChats.get(senderId) === receiverId) {
        // Save message to database
        const message = new Message({
          sender: senderId,
          receiver: receiverId,
          text: text
        });
        
        await message.save();
        await message.populate('sender', 'username email gender');
        
        // Emit to receiver
        const receiverSocketId = onlineUsers.get(receiverId);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('receiveMessage', message);
        }
        
        // Confirm to sender
        socket.emit('messageSent', { tempId, message });
      } else {
        socket.emit('messageError', { message: 'Not in a valid random chat session' });
      }
      
    } catch (error) {
      console.error('Error sending random message:', error);
      socket.emit('messageError', { message: 'Failed to send message' });
    }
  });

  // Get random chat status
  socket.on('get-random-chat-status', (data) => {
    const { userId } = data;
    const isWaiting = waitingUsers.has(userId);
    const isMatched = activeRandomChats.has(userId);
    const matchedWith = activeRandomChats.get(userId);
    
    socket.emit('random-chat-status', {
      isWaiting,
      isMatched,
      matchedWith,
      waitingCount: waitingUsers.size
    });
  });

  /* ----------------------------- WEBRTC SIGNALING ----------------------------- */

  socket.on('initiate-call', ({ to, from, callType, roomId }) => {
    console.log(`Call initiated: from=${from}, to=${to}, type=${callType}, room=${roomId}`);
    if (!socket.userId) {
      // If not set, set from so forwarding uses consistent value
      socket.userId = from;
      console.log(`Set socket.userId from payload: ${from}`);
    }

    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      activeCalls.set(roomId, { participants: [from, to], callType, initiator: from });
      io.to(receiverSocketId).emit('incoming-call', { from, callType, roomId, caller: { _id: from } });
      console.log(`Incoming call forwarded to ${to}`);
    } else {
      console.log(`Receiver ${to} not online`);
      socket.emit('call-error', { message: 'User is not online' });
    }
  });

  socket.on('accept-call', ({ to, from, roomId }) => {
    console.log(`Call accepted: from=${from} (callee), notify caller=${to}, room=${roomId}`);
    if (!socket.userId) {
      socket.userId = from;
      console.log(`Set socket.userId from payload: ${from}`);
    }
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('call-accepted', { from, roomId });
      console.log(`Notified caller ${to} that ${from} accepted`);
    } else {
      console.log(`Caller ${to} not online`);
    }
  });

  socket.on('reject-call', ({ to, from }) => {
    console.log(`Call rejected by ${from}, notify ${to}`);
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) io.to(receiverSocketId).emit('call-rejected', { from });
  });

  socket.on('end-call', ({ to, from }) => {
    console.log(`Call ended by ${from}, notifying:`, to);
    const recipients = Array.isArray(to) ? to : [to];
    recipients.forEach(recipientId => {
      const rid = onlineUsers.get(recipientId);
      if (rid) io.to(rid).emit('call-ended', { from });
    });
    // cleanup any call rooms that include 'from'
    for (const [rid, call] of activeCalls.entries()) {
      if (call.participants.includes(from)) {
        activeCalls.delete(rid);
        console.log(`Cleaned up call room ${rid}`);
      }
    }
  });

  // Join/Leave call room (useful for group calls or server-side room notifications)
  socket.on('join-call', ({ roomId, userId }) => {
    console.log(`User ${userId} joining room ${roomId}`);
    socket.join(roomId);
    const call = activeCalls.get(roomId);
    if (call && !call.participants.includes(userId)) call.participants.push(userId);
    socket.to(roomId).emit('user-joined-call', { userId, roomId });
  });

  socket.on('leave-call', ({ roomId, userId }) => {
    console.log(`User ${userId} leaving room ${roomId}`);
    socket.leave(roomId);
    socket.to(roomId).emit('user-left-call', { userId });
    const call = activeCalls.get(roomId);
    if (call) {
      call.participants = call.participants.filter(id => id !== userId);
      if (call.participants.length === 0) activeCalls.delete(roomId);
    }
  });

  // Forward WebRTC offer
  socket.on('webrtc-offer', ({ offer, to, roomId }) => {
    const from = socket.userId;
    console.log(`webrtc-offer: from=${from}, to=${to}, room=${roomId}`);
    if (!from) {
      socket.emit('call-error', { message: 'Socket not authenticated for signalling' });
      return;
    }
    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      socket.emit('call-error', { message: 'Recipient not online' });
      return;
    }
    io.to(receiverSocketId).emit('webrtc-offer', { offer, from, roomId });
    console.log(`Forwarded offer from ${from} to ${to}`);
  });

  // Forward WebRTC answer
  socket.on('webrtc-answer', ({ answer, to, roomId }) => {
    const from = socket.userId;
    console.log(`webrtc-answer: from=${from}, to=${to}, room=${roomId}`);
    if (!from) {
      socket.emit('call-error', { message: 'Socket not authenticated for signalling' });
      return;
    }
    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      socket.emit('call-error', { message: 'Recipient not online' });
      return;
    }
    io.to(receiverSocketId).emit('webrtc-answer', { answer, from, roomId });
    console.log(`Forwarded answer from ${from} to ${to}`);
  });

  // Forward ICE candidates
  socket.on('ice-candidate', ({ candidate, to, roomId }) => {
    const from = socket.userId;
    console.log(`ice-candidate: from=${from}, to=${to}, room=${roomId}`);
    if (!from) {
      socket.emit('call-error', { message: 'Socket not authenticated for signalling' });
      return;
    }
    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      // it's common for candidates to be sent before peer is fully registered; warn not fatal
      console.warn(`ice-candidate: recipient ${to} not online`);
      return;
    }
    io.to(receiverSocketId).emit('ice-candidate', { candidate, from, roomId });
    // no need to log every candidate in verbose environments - but helpful for debugging
  });

  /* ----------------------------- DISCONNECT ----------------------------- */
  socket.on('disconnect', (reason) => {
    console.log(`Socket disconnected: ${socket.id} (reason: ${reason})`);
    
    // remove from onlineUsers and waitingUsers
    for (const [userId, sockId] of onlineUsers.entries()) {
      if (sockId === socket.id) {
        onlineUsers.delete(userId);
        waitingUsers.delete(userId); // Also remove from waiting
        
        console.log(`User ${userId} removed from onlineUsers and waitingUsers`);
        
        // Handle random chat cleanup
        const partnerId = activeRandomChats.get(userId);
        if (partnerId) {
          const partnerSocketId = onlineUsers.get(partnerId);
          if (partnerSocketId) {
            io.to(partnerSocketId).emit('random-match-left');
          }
          activeRandomChats.delete(partnerId);
          activeRandomChats.delete(userId);
          
          // Clean up session
          for (const [sessionId, session] of randomChatSessions.entries()) {
            if (session.participants.includes(userId)) {
              randomChatSessions.delete(sessionId);
              break;
            }
          }
        }
        
        // notify participants in any active calls they left
        for (const [roomId, call] of activeCalls.entries()) {
          if (call.participants.includes(userId)) {
            call.participants.forEach(participantId => {
              if (participantId !== userId) {
                const participantSocket = onlineUsers.get(participantId);
                if (participantSocket) io.to(participantSocket).emit('user-left-call', { userId });
              }
            });
            call.participants = call.participants.filter(id => id !== userId);
            if (call.participants.length === 0) activeCalls.delete(roomId);
          }
        }
        break;
      }
    }
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  });
});

/* ----------------------------- ROUTES ----------------------------- */

app.get('/', (req, res) => {
  res.json({
    message: 'API is running!',
    endpoints: { 
      health: '/health', 
      signup: 'POST /signup', 
      anonymousSignup: 'POST /anonymous-signup', 
      login: 'POST /login', 
      logout: 'POST /logout', 
      profile: 'GET /me', 
      users: 'GET /users', 
      messages: 'GET /messages/:userId',
      randomChatStats: 'GET /random-chat/stats',
      randomChatStatus: 'GET /random-chat/status',
      leaveRandomChat: 'POST /random-chat/leave'
    }
  });
});

// anonymous signup
app.post('/anonymous-signup', async (req, res) => {
  try {
    let { username, gender } = req.body;
    if (!username || !gender) return res.status(400).json({ message: 'Username and gender required.' });
    let finalUsername = username.trim();
    let existing = await User.findOne({ username: finalUsername });
    if (existing) {
      let attempts = 0, maxAttempts = 10;
      while (existing && attempts < maxAttempts) {
        const suffix = Math.floor(Math.random() * 10000);
        finalUsername = `${username.trim()}${suffix}`;
        existing = await User.findOne({ username: finalUsername });
        attempts++;
      }
      if (existing) return res.status(409).json({ message: 'Could not generate unique username.' });
    }
    const user = new User({ username: finalUsername, gender, isAnonymous: true, tokenVersion: 0 });
    await user.save();
    const token = generateToken(user._id, user.tokenVersion);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.status(201).json({ message: 'Anonymous user created', user: { _id: user._id, username: user.username, gender: user.gender, token } });
  } catch (err) {
    console.error('anonymous-signup error:', err.message);
    if (err.code === 11000) return res.status(409).json({ message: 'Duplicate field' });
    res.status(500).json({ message: 'Internal server error' });
  }
});

// signup
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, gender } = req.body;
    if (!username || !email || !password || !gender) return res.status(400).json({ message: 'All fields required.' });
    if (password.length < 6) return res.status(400).json({ message: 'Password must be >= 6 chars.' });
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(409).json({ message: existing.email === email ? 'Email taken' : 'Username taken' });
    const user = new User({ username, email, password, gender, tokenVersion: 0, isAnonymous: false });
    await user.save();
    res.status(201).json({ message: 'User created', user: { id: user._id, username, email, gender } });
  } catch (err) {
    console.error('signup error:', err.message);
    if (err.code === 11000) return res.status(409).json({ message: 'Duplicate field' });
    res.status(500).json({ message: 'Internal server error' });
  }
});

// login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email & password required.' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });
    if (user.isAnonymous) return res.status(401).json({ message: 'Anonymous account - cannot log in via email.' });
    const ok = await user.comparePassword(password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials.' });
    user.tokenVersion += 1;
    await user.save();
    const token = generateToken(user._id, user.tokenVersion);
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ message: 'Login successful', user: { id: user._id, username: user.username, email: user.email, token } });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

app.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password -tokenVersion');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('/me error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { username, gender } = req.body;
    const userId = req.userId;
    if (username) {
      const exists = await User.findOne({ username, _id: { $ne: userId } });
      if (exists) return res.status(409).json({ message: 'Username taken' });
    }
    const updated = await User.findByIdAndUpdate(userId, { ...(username && { username }), ...(gender && { gender }) }, { new: true, runValidators: true }).select('-password -tokenVersion');
    if (!updated) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Profile updated', user: updated });
  } catch (err) {
    console.error('/profile error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/* messages */
app.post('/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, text } = req.body;
    if (!receiverId || !text) return res.status(400).json({ message: 'Receiver and text required' });
    const message = new Message({ sender: req.userId, receiver: receiverId, text });
    await message.save();
    const populated = await message.populate([{ path: 'sender', select: 'username email' }, { path: 'receiver', select: 'username email' }]);
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) io.to(receiverSocketId).emit('receiveMessage', populated);
    res.status(201).json(populated);
  } catch (err) {
    console.error('post /messages error:', err.message);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

app.get('/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const other = req.params.userId;
    const messages = await Message.find({ $or: [{ sender: req.userId, receiver: other }, { sender: other, receiver: req.userId }] }).sort({ createdAt: 1 }).populate('sender', 'username email').populate('receiver', 'username email');
    res.json(messages);
  } catch (err) {
    console.error('get /messages error:', err.message);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } }).select('_id username email gender');
    res.json(users);
  } catch (err) {
    console.error('get /users error:', err.message);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

/* ----------------------------- RANDOM CHAT ROUTES ----------------------------- */

// Get random chat statistics
app.get('/random-chat/stats', authenticateToken, async (req, res) => {
  try {
    const stats = {
      onlineUsers: onlineUsers.size,
      waitingUsers: waitingUsers.size,
      activeRandomChats: activeRandomChats.size / 2, // Divide by 2 since each chat has 2 entries
      activeSessions: randomChatSessions.size
    };
    res.json(stats);
  } catch (err) {
    console.error('random-chat/stats error:', err.message);
    res.status(500).json({ message: 'Failed to get stats' });
  }
});

// Get user's random chat status
app.get('/random-chat/status', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId.toString();
    const isWaiting = waitingUsers.has(userId);
    const isMatched = activeRandomChats.has(userId);
    const matchedWith = activeRandomChats.get(userId);
    
    let matchedUser = null;
    if (isMatched && matchedWith) {
      matchedUser = await User.findById(matchedWith).select('username gender _id');
    }
    
    res.json({
      isWaiting,
      isMatched,
      matchedWith: matchedUser,
      waitingCount: waitingUsers.size
    });
  } catch (err) {
    console.error('random-chat/status error:', err.message);
    res.status(500).json({ message: 'Failed to get status' });
  }
});

// Leave random chat
app.post('/random-chat/leave', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId.toString();
    
    // Remove from waiting
    waitingUsers.delete(userId);
    
    // If in active chat, notify partner and end chat
    const partnerId = activeRandomChats.get(userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) {
        io.to(partnerSocketId).emit('random-match-left');
      }
      activeRandomChats.delete(partnerId);
      activeRandomChats.delete(userId);
      
      // Clean up session
      for (const [sessionId, session] of randomChatSessions.entries()) {
        if (session.participants.includes(userId)) {
          randomChatSessions.delete(sessionId);
          break;
        }
      }
    }
    
    res.json({ message: 'Left random chat successfully' });
  } catch (err) {
    console.error('random-chat/leave error:', err.message);
    res.status(500).json({ message: 'Failed to leave random chat' });
  }
});

app.get('/health', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStates = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  res.json({
    status: dbState === 1 ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: { status: dbStates[dbState], host: mongoose.connection.host || 'not connected', name: mongoose.connection.name || 'not connected' },
    environment: process.env.NODE_ENV || 'development',
    onlineUsers: onlineUsers.size,
    activeCalls: activeCalls.size,
    randomChat: {
      waitingUsers: waitingUsers.size,
      activeChats: activeRandomChats.size / 2,
      activeSessions: randomChatSessions.size
    }
  });
});

// 404 and error handlers
app.use((req, res) => res.status(404).json({ message: 'Route not found', path: req.originalUrl }));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ message: 'Something went wrong', ...(process.env.NODE_ENV === 'development' && { error: err.message }) });
});

/* ----------------------------- START SERVER ----------------------------- */
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Client URL: ${process.env.CLIENT_URL || 'http://localhost:3000'}`);
  console.log(`🔑 JWT Secret: ${process.env.JWT_SECRET ? 'configured' : 'using default (INSECURE!)'}`);
  console.log(`📊 MongoDB URI: ${(process.env.MONGO_URI || process.env.MONGODB_URI) ? 'configured' : 'NOT CONFIGURED!'}`);
  console.log(`📞 WebRTC Signaling: ✅ ENABLED`);
  console.log(`🎲 Random Chat: ✅ ENABLED`);
});
