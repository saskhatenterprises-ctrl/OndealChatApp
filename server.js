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

// Socket.IO setup with improved configuration
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling'], // Allow both for better compatibility
  allowEIO3: true
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
const userSockets = new Map(); // socketId -> userId (reverse mapping)
const activeCalls = new Map(); // roomId -> { participants: [userId], callType, initiator }
const waitingUsers = new Map(); // userId -> { socketId, username }
const activeRandomChats = new Map(); // userId -> matchedUserId
const randomChatSessions = new Map(); // sessionId -> { participants, createdAt }
const randomChatPool = new Set(); // userId who are open to random chats

/* ----------------------------- SOCKET AUTH MIDDLEWARE ----------------------------- */

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');
    if (!token) {
      console.log('Socket connection rejected: No token provided');
      return next(new Error('Authentication required'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.userId) {
      return next(new Error('Invalid token'));
    }

    // Verify user exists
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return next(new Error('User not found'));
    }

    socket.userId = decoded.userId.toString();
    socket.username = user.username;
    console.log(`Socket authenticated for user ${socket.userId} (${socket.username}) - socket ${socket.id}`);
    return next();
  } catch (err) {
    console.warn('Socket auth failed:', err.message);
    return next(new Error('Authentication error'));
  }
});

/* ----------------------------- SOCKET.IO EVENTS ----------------------------- */

io.on('connection', (socket) => {
  console.log('✅ Socket connected:', socket.id, 'User:', socket.userId, socket.username);

  // Auto-register user
  if (socket.userId) {
    // Remove old socket if user reconnects
    const oldSocketId = onlineUsers.get(socket.userId);
    if (oldSocketId && oldSocketId !== socket.id) {
      console.log(`Removing old socket ${oldSocketId} for user ${socket.userId}`);
      userSockets.delete(oldSocketId);
    }

    onlineUsers.set(socket.userId, socket.id);
    userSockets.set(socket.id, socket.userId);
    randomChatPool.add(socket.userId);
    
    console.log(`✅ Auto-registered user ${socket.userId} (${socket.username}) -> socket ${socket.id}`);
    console.log(`📊 Total online users: ${onlineUsers.size}`);
    
    // Emit updated online users list
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    
    // Notify the user they're connected
    socket.emit('connection-success', { 
      userId: socket.userId, 
      socketId: socket.id,
      username: socket.username 
    });
    
    broadcastRandomChatAvailability();
  }

  // Helper function to broadcast availability
  function broadcastRandomChatAvailability() {
    const availableForMatching = Array.from(randomChatPool).filter(userId => 
      !activeRandomChats.has(userId)
    );
    const isAvailable = availableForMatching.length > 1;
    io.emit('random-chat-available', isAvailable);
  }

  // Helper function to auto-match users
  async function tryAutoMatch(userId) {
    try {
      const availableUsers = Array.from(randomChatPool).filter(id => 
        id !== userId && 
        !activeRandomChats.has(id) &&
        onlineUsers.has(id)
      );

      if (availableUsers.length > 0) {
        const matchedUserId = availableUsers[0];
        const [user, matchedUser] = await Promise.all([
          User.findById(userId).select('username email _id gender'),
          User.findById(matchedUserId).select('username email _id gender')
        ]);

        if (user && matchedUser) {
          waitingUsers.delete(userId);
          waitingUsers.delete(matchedUserId);
          
          activeRandomChats.set(userId, matchedUserId);
          activeRandomChats.set(matchedUserId, userId);
          
          const sessionId = `random-${Date.now()}`;
          randomChatSessions.set(sessionId, {
            participants: [userId, matchedUserId],
            createdAt: new Date()
          });

          const userSocketId = onlineUsers.get(userId);
          const matchedSocketId = onlineUsers.get(matchedUserId);
          
          if (userSocketId) {
            io.to(userSocketId).emit('random-match-found', matchedUser);
          }
          
          if (matchedSocketId) {
            io.to(matchedSocketId).emit('random-match-found', user);
          }
          
          console.log(`🎲 Auto-match created: ${userId} <-> ${matchedUserId}`);
          broadcastRandomChatAvailability();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('❌ Error in auto-match:', error);
      return false;
    }
  }

  /* ---------- MESSAGING - FIXED ---------- */
  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, text, tempId } = data;
      
      // Validate data
      if (!senderId || !receiverId || !text) {
        console.error('❌ Missing fields:', { senderId, receiverId, hasText: !!text });
        socket.emit('messageError', { message: 'Missing required fields', tempId });
        return;
      }

      // Verify sender matches socket
      if (senderId !== socket.userId) {
        console.error('❌ Sender mismatch:', senderId, 'vs', socket.userId);
        socket.emit('messageError', { message: 'Unauthorized', tempId });
        return;
      }

      console.log(`📤 Message: ${senderId} -> ${receiverId}: "${text.substring(0, 50)}..."`);

      // Save to database
      const message = new Message({ 
        sender: senderId, 
        receiver: receiverId, 
        text: text.substring(0, 1000).trim()
      });
      
      await message.save();
      
      // Populate sender and receiver info
      const populatedMessage = await Message.findById(message._id)
        .populate('sender', 'username email gender')
        .populate('receiver', 'username email gender')
        .lean()
        .exec();
      
      if (!populatedMessage) {
        throw new Error('Failed to populate message');
      }

      console.log('✅ Message saved:', populatedMessage._id);

      // Send to receiver if online
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', populatedMessage);
        console.log(`✅ Message delivered to ${receiverId} (socket: ${receiverSocketId})`);
      } else {
        console.log(`⚠️ Receiver ${receiverId} offline - message saved to DB`);
      }
      
      // Confirm to sender
      socket.emit('messageSent', { 
        tempId, 
        message: populatedMessage,
        success: true 
      });
      
      console.log(`✅ Message confirmed to sender ${senderId}`);
      
    } catch (err) {
      console.error('❌ sendMessage error:', err.message, err.stack);
      socket.emit('messageError', { 
        message: 'Failed to send message', 
        error: err.message,
        tempId: data?.tempId 
      });
    }
  });

  // Typing indicators - FIXED
  socket.on('typing', ({ senderId, receiverId }) => {
    if (!senderId || !receiverId) {
      console.error('❌ Typing: missing data');
      return;
    }
    
    // Verify sender
    if (senderId !== socket.userId) {
      console.error('❌ Typing: sender mismatch');
      return;
    }

    console.log(`⌨️ ${senderId} typing to ${receiverId}`);
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userTyping', { userId: senderId });
      console.log(`✅ Typing indicator sent to ${receiverId}`);
    }
  });

  socket.on('stopTyping', ({ senderId, receiverId }) => {
    if (!senderId || !receiverId) return;
    
    if (senderId !== socket.userId) return;

    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userStoppedTyping', { userId: senderId });
    }
  });

  /* ----------------------------- RANDOM CHAT EVENTS ----------------------------- */
  
  socket.on('check-random-chat-availability', () => {
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
      
      if (!userId || !socket.userId || userId !== socket.userId) {
        socket.emit('random-chat-error', { message: 'Authentication required' });
        return;
      }

      const user = await User.findById(userId);
      if (!user) {
        socket.emit('random-chat-error', { message: 'User not found' });
        return;
      }

      console.log(`🎲 User ${userId} (${username}) started random chat search`);
      
      if (activeRandomChats.has(userId)) {
        socket.emit('random-chat-error', { message: 'Already in a random chat' });
        return;
      }

      waitingUsers.set(userId, { socketId: socket.id, username: username || user.username });
      
      const matched = await tryAutoMatch(userId);
      
      if (!matched) {
        socket.emit('random-chat-waiting', { waitingCount: waitingUsers.size });
        console.log(`⏳ User ${userId} waiting. Total: ${waitingUsers.size}`);
      }
      
      broadcastRandomChatAvailability();
      
    } catch (error) {
      console.error('❌ Error in start-random-chat:', error);
      if (data.userId) waitingUsers.delete(data.userId);
      socket.emit('random-chat-error', { message: 'Failed to find match' });
      broadcastRandomChatAvailability();
    }
  });

  socket.on('stop-random-chat', async (data) => {
    const { userId } = data;
    
    if (!userId || userId !== socket.userId) return;
    
    console.log(`🛑 User ${userId} stopped random chat`);
    
    waitingUsers.delete(userId);
    
    const partnerId = activeRandomChats.get(userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) {
        io.to(partnerSocketId).emit('random-match-left');
        
        setTimeout(async () => {
          const rematched = await tryAutoMatch(partnerId);
          if (!rematched) {
            const partner = await User.findById(partnerId);
            if (partner && onlineUsers.has(partnerId)) {
              waitingUsers.set(partnerId, { socketId: partnerSocketId, username: partner.username });
              io.to(partnerSocketId).emit('random-chat-waiting', { waitingCount: waitingUsers.size });
            }
          }
        }, 1000);
      }
      
      activeRandomChats.delete(partnerId);
      activeRandomChats.delete(userId);
      
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

  /* ----------------------------- WEBRTC SIGNALING - IMPROVED ----------------------------- */

  socket.on('initiate-call', async ({ to, from, callType, roomId }) => {
    try {
      console.log(`📞 Call initiated: ${from} -> ${to}, type=${callType}, room=${roomId}`);
      
      // Verify sender
      if (from !== socket.userId) {
        console.error('❌ Call initiate: sender mismatch');
        socket.emit('call-error', { message: 'Unauthorized' });
        return;
      }

      const [caller, receiver] = await Promise.all([
        User.findById(from).select('username gender _id'),
        User.findById(to).select('username gender _id')
      ]);

      if (!caller || !receiver) {
        socket.emit('call-error', { message: 'User not found' });
        return;
      }

      const receiverSocketId = onlineUsers.get(to);
      if (!receiverSocketId) {
        console.log(`⚠️ Receiver ${to} not online`);
        socket.emit('call-error', { message: 'User is not online' });
        return;
      }

      // Store call info
      activeCalls.set(roomId, { 
        participants: [from, to], 
        callType, 
        initiator: from,
        caller: { _id: caller._id, username: caller.username, gender: caller.gender },
        createdAt: new Date()
      });
      
      // Notify receiver
      io.to(receiverSocketId).emit('incoming-call', { 
        from, 
        callType, 
        roomId, 
        caller: { _id: caller._id, username: caller.username, gender: caller.gender } 
      });
      
      console.log(`✅ Incoming call forwarded to ${to}`);
      
    } catch (error) {
      console.error('❌ Call initiation error:', error);
      socket.emit('call-error', { message: 'Failed to initiate call' });
    }
  });

  socket.on('accept-call', async ({ to, from, roomId }) => {
    try {
      console.log(`✅ Call accepted: ${from} accepted call from ${to}, room=${roomId}`);
      
      if (from !== socket.userId) {
        console.error('❌ Accept call: sender mismatch');
        return;
      }

      const receiverSocketId = onlineUsers.get(to);
      if (!receiverSocketId) {
        console.log(`⚠️ Caller ${to} not online`);
        socket.emit('call-error', { message: 'Caller is not online' });
        return;
      }

      // Update call participants
      const call = activeCalls.get(roomId);
      if (call) {
        if (!call.participants.includes(from)) {
          call.participants.push(from);
        }
      }

      io.to(receiverSocketId).emit('call-accepted', { from, roomId });
      console.log(`✅ Notified caller ${to} that ${from} accepted`);
      
    } catch (error) {
      console.error('❌ Accept call error:', error);
    }
  });

  socket.on('reject-call', ({ to, from }) => {
    console.log(`❌ Call rejected by ${from}, notify ${to}`);
    
    if (from !== socket.userId) return;

    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('call-rejected', { from });
    }

    // Clean up call
    for (const [roomId, call] of activeCalls.entries()) {
      if (call.participants.includes(from) && call.participants.includes(to)) {
        activeCalls.delete(roomId);
        console.log(`🗑️ Cleaned up rejected call room ${roomId}`);
        break;
      }
    }
  });

  socket.on('end-call', ({ to, from, roomId }) => {
    console.log(`📴 Call ended by ${from}, notifying:`, to, 'room:', roomId);
    
    if (from !== socket.userId) return;

    const recipients = Array.isArray(to) ? to : [to];
    recipients.forEach(recipientId => {
      const rid = onlineUsers.get(recipientId);
      if (rid) {
        io.to(rid).emit('call-ended', { from, roomId });
        console.log(`✅ Call end notification sent to ${recipientId}`);
      }
    });
    
    // Cleanup
    if (roomId) {
      activeCalls.delete(roomId);
      console.log(`🗑️ Cleaned up call room ${roomId}`);
    } else {
      // Cleanup any calls involving 'from'
      for (const [rid, call] of activeCalls.entries()) {
        if (call.participants.includes(from)) {
          activeCalls.delete(rid);
          console.log(`🗑️ Cleaned up call room ${rid}`);
        }
      }
    }
  });

  socket.on('join-call', ({ roomId, userId }) => {
    if (userId !== socket.userId) return;

    console.log(`👤 User ${userId} joining room ${roomId}`);
    socket.join(roomId);
    
    const call = activeCalls.get(roomId);
    if (call && !call.participants.includes(userId)) {
      call.participants.push(userId);
    }
    
    socket.to(roomId).emit('user-joined-call', { userId, roomId });
  });

  socket.on('leave-call', ({ roomId, userId }) => {
    if (userId !== socket.userId) return;

    console.log(`👋 User ${userId} leaving room ${roomId}`);
    socket.leave(roomId);
    socket.to(roomId).emit('user-left-call', { userId });
    
    const call = activeCalls.get(roomId);
    if (call) {
      call.participants = call.participants.filter(id => id !== userId);
      if (call.participants.length === 0) {
        activeCalls.delete(roomId);
        console.log(`🗑️ Empty call room ${roomId} deleted`);
      }
    }
  });

  // WebRTC Signaling - IMPROVED
  socket.on('webrtc-offer', ({ offer, to, roomId }) => {
    const from = socket.userId;
    console.log(`🔄 webrtc-offer: ${from} -> ${to}, room=${roomId}`);
    
    if (!from) {
      socket.emit('call-error', { message: 'Not authenticated' });
      return;
    }

    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      console.error(`⚠️ Recipient ${to} not online for offer`);
      socket.emit('call-error', { message: 'Recipient not online' });
      return;
    }

    io.to(receiverSocketId).emit('webrtc-offer', { offer, from, roomId });
    console.log(`✅ Offer forwarded to ${to}`);
  });

  socket.on('webrtc-answer', ({ answer, to, roomId }) => {
    const from = socket.userId;
    console.log(`🔄 webrtc-answer: ${from} -> ${to}, room=${roomId}`);
    
    if (!from) {
      socket.emit('call-error', { message: 'Not authenticated' });
      return;
    }

    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      console.error(`⚠️ Recipient ${to} not online for answer`);
      socket.emit('call-error', { message: 'Recipient not online' });
      return;
    }

    io.to(receiverSocketId).emit('webrtc-answer', { answer, from, roomId });
    console.log(`✅ Answer forwarded to ${to}`);
  });

  socket.on('ice-candidate', ({ candidate, to, roomId }) => {
    const from = socket.userId;
    
    if (!from) {
      socket.emit('call-error', { message: 'Not authenticated' });
      return;
    }

    const receiverSocketId = onlineUsers.get(to);
    if (!receiverSocketId) {
      console.warn(`⚠️ ICE candidate: recipient ${to} not online`);
      return;
    }

    io.to(receiverSocketId).emit('ice-candidate', { candidate, from, roomId });
  });

  /* ----------------------------- DISCONNECT ----------------------------- */
  socket.on('disconnect', async (reason) => {
    console.log(`🔌 Socket disconnected: ${socket.id} (User: ${socket.userId}) - Reason: ${reason}`);
    
    if (socket.userId) {
      // Clean up user mappings
      onlineUsers.delete(socket.userId);
      userSockets.delete(socket.id);
      waitingUsers.delete(socket.userId);
      randomChatPool.delete(socket.userId);
      
      console.log(`🗑️ User ${socket.userId} removed from online users`);
      
      // Handle random chat cleanup
      const partnerId = activeRandomChats.get(socket.userId);
      if (partnerId) {
        const partnerSocketId = onlineUsers.get(partnerId);
        if (partnerSocketId) {
          io.to(partnerSocketId).emit('random-match-left');
          
          setTimeout(async () => {
            const rematched = await tryAutoMatch(partnerId);
            if (!rematched) {
              try {
                const partner = await User.findById(partnerId);
                if (partner && onlineUsers.has(partnerId)) {
                  waitingUsers.set(partnerId, { socketId: partnerSocketId, username: partner.username });
                  io.to(partnerSocketId).emit('random-chat-waiting', { waitingCount: waitingUsers.size });
                }
              } catch (err) {
                console.error('❌ Error auto-rematching partner:', err);
              }
            }
          }, 1000);
        }
        
        activeRandomChats.delete(partnerId);
        activeRandomChats.delete(socket.userId);
        
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
          // Notify other participants
          call.participants.forEach(participantId => {
            if (participantId !== socket.userId) {
              const participantSocket = onlineUsers.get(participantId);
              if (participantSocket) {
                io.to(participantSocket).emit('user-left-call', { userId: socket.userId });
                io.to(participantSocket).emit('call-ended', { from: socket.userId, roomId });
              }
            }
          });
          
          call.participants = call.participants.filter(id => id !== socket.userId);
          if (call.participants.length === 0) {
            activeCalls.delete(roomId);
            console.log(`🗑️ Empty call room ${roomId} deleted`);
          }
        }
      }
    }
    
    // Broadcast updated online users
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    broadcastRandomChatAvailability();
    
    console.log(`📊 Remaining online users: ${onlineUsers.size}`);
  });
});

/* ----------------------------- ROUTES ----------------------------- */

app.get('/', (req, res) => {
  res.json({
    message: 'API is running!',
    version: '2.0',
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

// Messages - IMPROVED
app.post('/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, text } = req.body;
    if (!receiverId || !text) {
      return res.status(400).json({ message: 'Receiver and text required' });
    }
    
    // Verify receiver exists
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ message: 'Receiver not found' });
    }
    
    const message = new Message({ 
      sender: req.userId, 
      receiver: receiverId, 
      text: text.substring(0, 1000).trim() 
    });
    await message.save();
    
    const populated = await Message.findById(message._id)
      .populate('sender', 'username email gender')
      .populate('receiver', 'username email gender')
      .lean()
      .exec();
    
    // Send real-time notification
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('receiveMessage', populated);
      console.log(`📨 REST API: Message sent to ${receiverId}`);
    }
    
    res.status(201).json(populated);
  } catch (err) {
    console.error('post /messages error:', err.message);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

app.get('/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const other = req.params.userId;
    
    // Verify other user exists
    const otherUser = await User.findById(other);
    if (!otherUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const messages = await Message.find({ 
      $or: [
        { sender: req.userId, receiver: other }, 
        { sender: other, receiver: req.userId }
      ] 
    })
    .sort({ createdAt: 1 })
    .populate('sender', 'username email gender')
    .populate('receiver', 'username email gender')
    .lean()
    .exec();
    
    res.json(messages);
  } catch (err) {
    console.error('get /messages error:', err.message);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } })
      .select('_id username email gender isAnonymous createdAt')
      .sort({ createdAt: -1 })
      .lean();
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
      activeSessions: randomChatSessions.size,
      randomChatPool: randomChatPool.size
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
    
    waitingUsers.delete(userId);
    
    const partnerId = activeRandomChats.get(userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) {
        io.to(partnerSocketId).emit('random-match-left');
      }
      activeRandomChats.delete(partnerId);
      activeRandomChats.delete(userId);
      
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

// Debug endpoint
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
  
  const waitingUsersArray = Array.from(waitingUsers.entries()).map(([userId, data]) => ({
    userId,
    ...data
  }));
  
  res.json({
    onlineUsers: onlineUsersArray,
    randomChatPool: randomChatPoolArray,
    activeRandomChats: activeChatsArray,
    waitingUsers: waitingUsersArray,
    activeCalls: Array.from(activeCalls.entries()).map(([roomId, data]) => ({
      roomId,
      ...data
    })),
    stats: {
      totalOnline: onlineUsers.size,
      totalInPool: randomChatPool.size,
      totalActiveChats: activeRandomChats.size / 2,
      totalWaiting: waitingUsers.size,
      totalActiveCalls: activeCalls.size
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    message: 'Route not found', 
    path: req.originalUrl,
    method: req.method
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  res.status(500).json({ 
    message: 'Something went wrong', 
    ...(process.env.NODE_ENV === 'development' && { error: err.message, stack: err.stack }) 
  });
});

/* ----------------------------- START SERVER ----------------------------- */
const PORT = process.env.PORT || 5000;

// Validate environment variables
const requiredEnvVars = ['JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  process.exit(1);
}

if (process.env.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
  console.warn('⚠️  WARNING: Using default JWT secret. This is insecure for production!');
}

server.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 Server running on port', PORT);
  console.log('📍 Environment:', process.env.NODE_ENV || 'development');
  console.log('🌐 Client URL:', process.env.CLIENT_URL || 'http://localhost:3000');
  console.log('🔑 JWT Secret:', process.env.JWT_SECRET ? '✅ configured' : '❌ NOT CONFIGURED!');
  console.log('📊 MongoDB URI:', (process.env.MONGO_URI || process.env.MONGODB_URI) ? '✅ configured' : '❌ NOT CONFIGURED!');
  console.log('📞 WebRTC Signaling: ✅ ENABLED');
  console.log('🎲 Random Chat: ✅ ENABLED');
  console.log('💬 Real-time Messaging: ✅ ENABLED');
  console.log('='.repeat(60));
});
