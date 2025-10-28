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

// CORS config
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

// Socket.IO setup
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
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

    mongoose.connection.on('connected', () => {
      console.log('✅ MongoDB connected successfully');
    });

    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ MongoDB disconnected');
    });

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

/* ----------------------------- SOCKET DATA STRUCTURES ----------------------------- */

const onlineUsers = new Map(); // userId -> socketId
const activeCalls = new Map(); // roomId -> { participants: [userId], callType, initiator }
const waitingUsers = new Map(); // userId -> { socketId, username }
const activeRandomChats = new Map(); // userId -> matchedUserId
const randomChatSessions = new Map(); // sessionId -> { participants, createdAt }
const randomChatPool = new Set(); // userId who are open to random chats (online + waiting)

/* ----------------------------- SOCKET AUTH MIDDLEWARE ----------------------------- */

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');
    if (!token) {
      console.log('Socket connection rejected: No token provided');
      return next(new Error('Authentication required'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded && decoded.userId) {
      socket.userId = decoded.userId.toString();
      console.log(`Socket authenticated for user ${socket.userId} (socket ${socket.id})`);
      return next();
    } else {
      return next(new Error('Invalid token'));
    }
  } catch (err) {
    console.warn('Socket auth failed:', err.message);
    return next(new Error('Authentication error'));
  }
});

/* ----------------------------- SOCKET.IO EVENTS ----------------------------- */

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id, 'User:', socket.userId);

  // Auto-register user
  if (socket.userId) {
    onlineUsers.set(socket.userId, socket.id);
    randomChatPool.add(socket.userId); // Automatically add to random chat pool
    console.log(`Auto-registered user ${socket.userId} -> socket ${socket.id}`);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    
    // Broadcast random chat availability
    broadcastRandomChatAvailability();
  }

  // Helper function to broadcast availability
  function broadcastRandomChatAvailability() {
    // Available if there are users in random chat pool (excluding those already matched)
    const availableForMatching = Array.from(randomChatPool).filter(userId => 
      !activeRandomChats.has(userId)
    );
    const isAvailable = availableForMatching.length > 1; // Need at least 2 for matching
    io.emit('random-chat-available', isAvailable);
  }

  // Helper function to auto-match users
  async function tryAutoMatch(userId) {
    try {
      // Find available users in the pool (not already matched, not this user)
      const availableUsers = Array.from(randomChatPool).filter(id => 
        id !== userId && 
        !activeRandomChats.has(id) &&
        onlineUsers.has(id) // Must be online
      );

      if (availableUsers.length > 0) {
        const matchedUserId = availableUsers[0];
        const [user, matchedUser] = await Promise.all([
          User.findById(userId).select('username email _id gender'),
          User.findById(matchedUserId).select('username email _id gender')
        ]);

        if (user && matchedUser) {
          // Remove from waiting if they were waiting
          waitingUsers.delete(userId);
          waitingUsers.delete(matchedUserId);
          
          // Create chat session
          activeRandomChats.set(userId, matchedUserId);
          activeRandomChats.set(matchedUserId, userId);
          
          const sessionId = `random-${Date.now()}`;
          randomChatSessions.set(sessionId, {
            participants: [userId, matchedUserId],
            createdAt: new Date()
          });

          // Notify both users
          const userSocketId = onlineUsers.get(userId);
          const matchedSocketId = onlineUsers.get(matchedUserId);
          
          if (userSocketId) {
            io.to(userSocketId).emit('random-match-found', matchedUser);
          }
          
          if (matchedSocketId) {
            io.to(matchedSocketId).emit('random-match-found', user);
          }
          
          console.log(`Auto-match created: ${userId} <-> ${matchedUserId}`);
          
          // Broadcast updated availability
          broadcastRandomChatAvailability();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Error in auto-match:', error);
      return false;
    }
  }

  // Explicit registration
  socket.on('register', async (userId) => {
    if (!userId) {
      socket.emit('error', { message: 'User ID required' });
      return;
    }

    try {
      const user = await User.findById(userId);
      if (!user) {
        socket.emit('error', { message: 'User not found' });
        return;
      }

      socket.userId = userId.toString();
      onlineUsers.set(socket.userId, socket.id);
      randomChatPool.add(socket.userId); // Add to random chat pool
      console.log(`User registered: ${socket.userId} -> socket ${socket.id}`);
      io.emit('onlineUsers', Array.from(onlineUsers.keys()));
      
      broadcastRandomChatAvailability();
    } catch (err) {
      console.error('Registration error:', err);
      socket.emit('error', { message: 'Registration failed' });
    }
  });

  /* ---------- Messaging ---------- */
  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, text, tempId } = data;
      
      if (!senderId || !receiverId || !text) {
        socket.emit('messageError', { message: 'Missing required fields' });
        return;
      }

      console.log(`Message from ${senderId} to ${receiverId}: ${text.substring(0, 50)}...`);

      // Check if this is a random chat message
      const isRandomChat = activeRandomChats.get(senderId) === receiverId;
      
      // Save message to database
      const message = new Message({ 
        sender: senderId, 
        receiver: receiverId, 
        text: text.substring(0, 1000)
      });
      
      await message.save();
      
      const populatedMessage = await Message.findById(message._id)
        .populate('sender', 'username email')
        .populate('receiver', 'username email')
        .exec();
      
      if (!populatedMessage) {
        throw new Error('Failed to populate message');
      }

      // Send to receiver
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', populatedMessage);
        console.log(`Message delivered to ${receiverId} (socket: ${receiverSocketId})`);
      } else {
        console.log(`Receiver ${receiverId} not online`);
      }
      
      // Confirm to sender
      socket.emit('messageSent', { tempId, message: populatedMessage });
      
    } catch (err) {
      console.error('sendMessage error:', err.message);
      socket.emit('messageError', { message: 'Failed to send message', error: err.message });
    }
  });

  socket.on('typing', ({ senderId, receiverId }) => {
    if (!senderId || !receiverId) return;
    console.log(`${senderId} typing to ${receiverId}`);
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userTyping', { userId: senderId });
      console.log(`Typing indicator sent to ${receiverId}`);
    }
  });

  socket.on('stopTyping', ({ senderId, receiverId }) => {
    if (!senderId || !receiverId) return;
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userStoppedTyping', { userId: senderId });
    }
  });

  /* ----------------------------- RANDOM CHAT EVENTS ----------------------------- */
  
  socket.on('check-random-chat-availability', () => {
    // Check if there are other users in the pool who could match
    const availableForMatching = Array.from(randomChatPool).filter(userId => 
      userId !== socket.userId && 
      !activeRandomChats.has(userId) &&
      onlineUsers.has(userId)
    );
    const isAvailable = availableForMatching.length > 0;
    socket.emit('random-chat-available', isAvailable);
  });

  socket.on('start-random-chat', async (data) => {
    try {
      const { userId, username } = data;
      
      if (!userId || !socket.userId) {
        socket.emit('random-chat-error', { message: 'Authentication required' });
        return;
      }

      // Verify user exists
      const user = await User.findById(userId);
      if (!user) {
        socket.emit('random-chat-error', { message: 'User not found' });
        return;
      }

      console.log(`User ${userId} (${username}) started random chat search`);
      
      // Check if already in a chat
      if (activeRandomChats.has(userId)) {
        socket.emit('random-chat-error', { message: 'Already in a random chat' });
        return;
      }

      // Add to waiting pool
      waitingUsers.set(userId, { socketId: socket.id, username: username || user.username });
      
      // Try to find an immediate match from the random chat pool
      const matched = await tryAutoMatch(userId);
      
      if (!matched) {
        // No match found yet, user is waiting
        socket.emit('random-chat-waiting', { waitingCount: waitingUsers.size });
        console.log(`User ${userId} added to waiting pool. Total waiting: ${waitingUsers.size}`);
      }
      
      // Broadcast updated availability
      broadcastRandomChatAvailability();
      
    } catch (error) {
      console.error('Error in start-random-chat:', error);
      if (data.userId) waitingUsers.delete(data.userId);
      socket.emit('random-chat-error', { message: 'Failed to find match' });
      broadcastRandomChatAvailability();
    }
  });

  socket.on('stop-random-chat', (data) => {
    const { userId } = data;
    
    if (!userId) return;
    
    console.log(`User ${userId} stopped random chat`);
    
    // Remove from waiting
    waitingUsers.delete(userId);
    
    // If in active chat, notify partner
    const partnerId = activeRandomChats.get(userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) {
        io.to(partnerSocketId).emit('random-match-left');
        
        // Auto-match the partner with someone new
        setTimeout(async () => {
          const rematched = await tryAutoMatch(partnerId);
          if (!rematched) {
            // Add partner to waiting pool for next match
            const partner = await User.findById(partnerId);
            if (partner) {
              waitingUsers.set(partnerId, { socketId: partnerSocketId, username: partner.username });
              io.to(partnerSocketId).emit('random-chat-waiting', { waitingCount: waitingUsers.size });
            }
          }
        }, 1000);
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
    broadcastRandomChatAvailability();
  });

  /* ----------------------------- WEBRTC SIGNALING ----------------------------- */

  socket.on('initiate-call', async ({ to, from, callType, roomId }) => {
    try {
      console.log(`Call initiated: from=${from}, to=${to}, type=${callType}, room=${roomId}`);
      
      if (!socket.userId) {
        socket.userId = from;
      }

      // Verify both users exist
      const [caller, receiver] = await Promise.all([
        User.findById(from),
        User.findById(to)
      ]);

      if (!caller || !receiver) {
        socket.emit('call-error', { message: 'User not found' });
        return;
      }

      const receiverSocketId = onlineUsers.get(to);
      if (receiverSocketId) {
        activeCalls.set(roomId, { 
          participants: [from, to], 
          callType, 
          initiator: from,
          caller: { _id: caller._id, username: caller.username }
        });
        
        io.to(receiverSocketId).emit('incoming-call', { 
          from, 
          callType, 
          roomId, 
          caller: { _id: caller._id, username: caller.username } 
        });
        
        console.log(`Incoming call forwarded to ${to}`);
      } else {
        console.log(`Receiver ${to} not online`);
        socket.emit('call-error', { message: 'User is not online' });
      }
    } catch (error) {
      console.error('Call initiation error:', error);
      socket.emit('call-error', { message: 'Failed to initiate call' });
    }
  });

  socket.on('accept-call', ({ to, from, roomId }) => {
    console.log(`Call accepted: from=${from} (callee), notify caller=${to}, room=${roomId}`);
    if (!socket.userId) {
      socket.userId = from;
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
    
    // Cleanup call rooms that include 'from'
    for (const [rid, call] of activeCalls.entries()) {
      if (call.participants.includes(from)) {
        activeCalls.delete(rid);
        console.log(`Cleaned up call room ${rid}`);
      }
    }
  });

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
  });

  // Forward ICE candidates
  socket.on('ice-candidate', ({ candidate, to, roomId }) => {
    const from = socket.userId;
    if (!from) {
      socket.emit('call-error', { message: 'Socket not authenticated for signalling' });
      return;
    }
    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      console.warn(`ice-candidate: recipient ${to} not online`);
      return;
    }
    io.to(receiverSocketId).emit('ice-candidate', { candidate, from, roomId });
  });

  /* ----------------------------- DISCONNECT ----------------------------- */
  socket.on('disconnect', async (reason) => {
    console.log(`Socket disconnected: ${socket.id} (reason: ${reason})`);
    
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      waitingUsers.delete(socket.userId);
      randomChatPool.delete(socket.userId);
      
      console.log(`User ${socket.userId} removed from online/waiting users`);
      
      // Handle random chat cleanup
      const partnerId = activeRandomChats.get(socket.userId);
      if (partnerId) {
        const partnerSocketId = onlineUsers.get(partnerId);
        if (partnerSocketId) {
          io.to(partnerSocketId).emit('random-match-left');
          
          // Auto-match the partner with someone new after a brief delay
          setTimeout(async () => {
            const rematched = await tryAutoMatch(partnerId);
            if (!rematched) {
              // Add partner to waiting pool for next match
              try {
                const partner = await User.findById(partnerId);
                if (partner && onlineUsers.has(partnerId)) {
                  waitingUsers.set(partnerId, { socketId: partnerSocketId, username: partner.username });
                  io.to(partnerSocketId).emit('random-chat-waiting', { waitingCount: waitingUsers.size });
                }
              } catch (err) {
                console.error('Error auto-rematching partner:', err);
              }
            }
          }, 1000);
        }
        
        activeRandomChats.delete(partnerId);
        activeRandomChats.delete(socket.userId);
        
        // Clean up session
        for (const [sessionId, session] of randomChatSessions.entries()) {
          if (session.participants.includes(socket.userId)) {
            randomChatSessions.delete(sessionId);
            break;
          }
        }
      }
      
      // Clean up active calls
      for (const [roomId, call] of activeCalls.entries()) {
        if (call.participants.includes(socket.userId)) {
          call.participants.forEach(participantId => {
            if (participantId !== socket.userId) {
              const participantSocket = onlineUsers.get(participantId);
              if (participantSocket) io.to(participantSocket).emit('user-left-call', { userId: socket.userId });
            }
          });
          call.participants = call.participants.filter(id => id !== socket.userId);
          if (call.participants.length === 0) activeCalls.delete(roomId);
        }
      }
    }
    
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    broadcastRandomChatAvailability();
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
      updateProfile: 'PUT /profile',
      users: 'GET /users', 
      messages: 'GET /messages/:userId',
      sendMessage: 'POST /messages',
      randomChatStats: 'GET /random-chat/stats',
      randomChatStatus: 'GET /random-chat/status',
      leaveRandomChat: 'POST /random-chat/leave'
    }
  });
});

// Anonymous signup
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
    
    res.status(201).json({ 
      message: 'Anonymous user created', 
      user: { 
        _id: user._id, 
        username: user.username, 
        gender: user.gender, 
        token 
      } 
    });
  } catch (err) {
    console.error('anonymous-signup error:', err.message);
    if (err.code === 11000) return res.status(409).json({ message: 'Duplicate field' });
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Regular signup
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, gender } = req.body;
    if (!username || !email || !password || !gender) {
      return res.status(400).json({ message: 'All fields required.' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be >= 6 chars.' });
    }
    
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({ 
        message: existing.email === email ? 'Email taken' : 'Username taken' 
      });
    }
    
    const user = new User({ username, email, password, gender, tokenVersion: 0, isAnonymous: false });
    await user.save();
    
    res.status(201).json({ 
      message: 'User created', 
      user: { 
        id: user._id, 
        username, 
        email, 
        gender 
      } 
    });
  } catch (err) {
    console.error('signup error:', err.message);
    if (err.code === 11000) return res.status(409).json({ message: 'Duplicate field' });
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email & password required.' });
    }
    
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });
    
    if (user.isAnonymous) {
      return res.status(401).json({ message: 'Anonymous account - cannot log in via email.' });
    }
    
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
    
    res.json({ 
      message: 'Login successful', 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email, 
        token 
      } 
    });
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
    
    const updated = await User.findByIdAndUpdate(
      userId, 
      { ...(username && { username }), ...(gender && { gender }) }, 
      { new: true, runValidators: true }
    ).select('-password -tokenVersion');
    
    if (!updated) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Profile updated', user: updated });
  } catch (err) {
    console.error('/profile error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Messages
app.post('/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, text } = req.body;
    if (!receiverId || !text) return res.status(400).json({ message: 'Receiver and text required' });
    
    const message = new Message({ sender: req.userId, receiver: receiverId, text });
    await message.save();
    
    const populated = await message.populate([
      { path: 'sender', select: 'username email' }, 
      { path: 'receiver', select: 'username email' }
    ]);
    
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
    const messages = await Message.find({ 
      $or: [
        { sender: req.userId, receiver: other }, 
        { sender: other, receiver: req.userId }
      ] 
    })
    .sort({ createdAt: 1 })
    .populate('sender', 'username email')
    .populate('receiver', 'username email');
    
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

app.get('/random-chat/stats', authenticateToken, async (req, res) => {
  try {
    const stats = {
      onlineUsers: onlineUsers.size,
      waitingUsers: waitingUsers.size,
      activeRandomChats: activeRandomChats.size / 2,
      activeSessions: randomChatSessions.size
    };
    res.json(stats);
  } catch (err) {
    console.error('random-chat/stats error:', err.message);
    res.status(500).json({ message: 'Failed to get stats' });
  }
});

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
    database: { 
      status: dbStates[dbState], 
      host: mongoose.connection.host || 'not connected', 
      name: mongoose.connection.name || 'not connected' 
    },
    environment: process.env.NODE_ENV || 'development',
    onlineUsers: onlineUsers.size,
    activeCalls: activeCalls.size,
    randomChat: {
      poolSize: randomChatPool.size,
      waitingUsers: waitingUsers.size,
      activeChats: activeRandomChats.size / 2,
      activeSessions: randomChatSessions.size
    },
    sockets: {
      connectedSockets: io.sockets.sockets.size
    }
  });
});

// Debug endpoint to check socket mappings
app.get('/debug/sockets', authenticateToken, (req, res) => {
  const onlineUsersArray = Array.from(onlineUsers.entries()).map(([userId, socketId]) => ({
    userId,
    socketId
  }));
  
  const randomChatPoolArray = Array.from(randomChatPool);
  const activeChatsArray = Array.from(activeRandomChats.entries()).map(([userId, partnerId]) => ({
    userId,
    partnerId
  }));
  
  res.json({
    onlineUsers: onlineUsersArray,
    randomChatPool: randomChatPoolArray,
    activeRandomChats: activeChatsArray,
    totalOnline: onlineUsers.size,
    totalInPool: randomChatPool.size,
    totalActiveChats: activeRandomChats.size / 2
  });
});

// 404 and error handlers
app.use((req, res) => {
  res.status(404).json({ 
    message: 'Route not found', 
    path: req.originalUrl 
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ 
    message: 'Something went wrong', 
    ...(process.env.NODE_ENV === 'development' && { error: err.message }) 
  });
});

/* ----------------------------- START SERVER ----------------------------- */
const PORT = process.env.PORT || 5000;

// Validate environment variables
const requiredEnvVars = ['JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('Missing required environment variables:', missingEnvVars);
  process.exit(1);
}

if (process.env.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
  console.warn('⚠️  WARNING: Using default JWT secret. This is insecure for production!');
}

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Client URL: ${process.env.CLIENT_URL || 'http://localhost:3000'}`);
  console.log(`🔑 JWT Secret: ${process.env.JWT_SECRET ? 'configured' : 'using default (INSECURE!)'}`);
  console.log(`📊 MongoDB URI: ${(process.env.MONGO_URI || process.env.MONGODB_URI) ? 'configured' : 'NOT CONFIGURED!'}`);
  console.log(`📞 WebRTC Signaling: ✅ ENABLED`);
  console.log(`🎲 Random Chat: ✅ ENABLED`);
});
