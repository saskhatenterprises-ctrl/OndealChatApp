const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

app.use(express.json());
app.use(cookieParser());

const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:3000')
  .split(',')
  .map(origin => origin.trim());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`❌ Not allowed by CORS: ${origin}`));
    }
  },
  credentials: true
}));

// Socket.IO setup with CORS
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  }
});

// MongoDB connection with improved error handling
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI || process.env.MONGODB_URI;
    
    if (!mongoURI) {
      throw new Error('MONGO_URI or MONGODB_URI is not defined in environment variables');
    }

    console.log('🔄 Attempting to connect to MongoDB...');
    
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

    console.log(`✅ MongoDB Connected Successfully!`);
    console.log(`📂 Database: ${conn.connection.name}`);
    console.log(`🔗 Host: ${conn.connection.host}`);

    // Fix email index issue for anonymous users
    try {
      console.log('🔧 Checking email index...');
      const collections = await mongoose.connection.db.listCollections({ name: 'users' }).toArray();
      
      if (collections.length > 0) {
        const indexes = await mongoose.connection.db.collection('users').indexes();
        const emailIndex = indexes.find(idx => idx.key.email === 1);
        
        if (emailIndex && emailIndex.sparse) {
          console.log('✅ Email index is already sparse. Perfect!');
        } else if (emailIndex && !emailIndex.sparse) {
          console.log('⚠️ Found non-sparse email index. Dropping and recreating...');
          await mongoose.connection.db.collection('users').dropIndex('email_1');
          await mongoose.connection.db.collection('users').createIndex(
            { email: 1 }, 
            { unique: true, sparse: true, name: 'email_1' }
          );
          console.log('✅ Email index updated to sparse successfully!');
        } else if (!emailIndex) {
          console.log('➕ Creating sparse email index...');
          await mongoose.connection.db.collection('users').createIndex(
            { email: 1 }, 
            { unique: true, sparse: true, name: 'email_1' }
          );
          console.log('✅ Sparse email index created!');
        }
      }
    } catch (indexError) {
      console.error('⚠️ Index check note:', indexError.message);
      // This is usually fine - index already exists correctly
    }

    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err.message);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ Mongoose disconnected from MongoDB');
    });

    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('🔒 MongoDB connection closed due to app termination');
      process.exit(0);
    });

  } catch (error) {
    console.error('❌ Database connection failed!');
    console.error('Error message:', error.message);
    
    if (error.message.includes('querySrv ECONNREFUSED')) {
      console.error('💡 DNS Resolution Error - Possible fixes:');
      console.error('   1. Check your internet connection');
      console.error('   2. Verify MongoDB Atlas cluster is running');
      console.error('   3. Check IP whitelist in MongoDB Atlas (allow 0.0.0.0/0 for testing)');
      console.error('   4. Verify your MONGO_URI format: mongodb+srv://username:password@cluster.xxx.mongodb.net/dbname');
    }
    
    if (process.env.NODE_ENV === 'production') {
      console.log('⏳ Retrying connection in 10 seconds...');
      setTimeout(connectDB, 10000);
    } else {
      process.exit(1);
    }
  }
};

connectDB();

/* ----------------------------- SCHEMAS ----------------------------- */

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true, 
    minlength: 2, 
    maxlength: 30 
  },
  email: { 
    type: String, 
    sparse: true, // This creates a sparse index that ignores null/undefined values
    lowercase: true, 
    trim: true, 
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    minlength: 6 
  },
  gender: { 
    type: String, 
    required: true, 
    enum: ['male', 'female', 'other', 'trans', 'prefer-not-to-say'] 
  },
  isAnonymous: {
    type: Boolean,
    default: false
  },
  tokenVersion: {
    type: Number,
    default: 0
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Create sparse index for email (allows multiple null/undefined values)
userSchema.index({ email: 1 }, { unique: true, sparse: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  // Skip password hashing for anonymous users without password
  if (this.isAnonymous && !this.password) {
    return next();
  }
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
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

/* ----------------------------- AUTH MIDDLEWARE ----------------------------- */

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

if (!process.env.JWT_SECRET) {
  console.warn('⚠️ WARNING: Using default JWT_SECRET. Set JWT_SECRET in .env for production!');
}

const generateToken = (userId, tokenVersion) => {
  return jwt.sign(
    { userId, tokenVersion }, 
    JWT_SECRET, 
    { expiresIn: '7d' }
  );
};

const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      console.log('❌ No token provided');
      return res.status(401).json({ 
        message: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('✅ Token decoded:', decoded);

    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      console.log('❌ User not found for ID:', decoded.userId);
      return res.status(401).json({ 
        message: 'User not found.',
        code: 'USER_NOT_FOUND'
      });
    }

    if (user.tokenVersion === undefined || user.tokenVersion === null) {
      console.log('⚠️ User missing tokenVersion, initializing to 0');
      user.tokenVersion = 0;
      await user.save();
    }

    if (decoded.tokenVersion === undefined) {
      console.log('⚠️ Old token without tokenVersion detected, treating as invalid');
      return res.status(401).json({ 
        message: 'Your session is outdated. Please login again.',
        code: 'OLD_TOKEN_FORMAT'
      });
    }

    if (decoded.tokenVersion !== user.tokenVersion) {
      console.log(`❌ Token version mismatch. Token: ${decoded.tokenVersion}, DB: ${user.tokenVersion}`);
      return res.status(401).json({ 
        message: 'Session expired. You have been logged in from another device.',
        code: 'SESSION_INVALIDATED'
      });
    }

    console.log('✅ Token version valid for user:', user.username);
    req.userId = decoded.userId;
    req.user = user;
    next();

  } catch (error) {
    console.error('❌ Authentication error:', error.message);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired. Please login again.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        message: 'Invalid token.',
        code: 'INVALID_TOKEN'
      });
    }

    res.status(500).json({ 
      message: 'Authentication failed.',
      code: 'AUTH_ERROR'
    });
  }
};

/* ----------------------------- SOCKET.IO ----------------------------- */

const onlineUsers = new Map();
const activeCalls = new Map(); // Track active calls: roomId -> { participants, callType }

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  socket.on('register', (userId) => {
    if (userId) {
      onlineUsers.set(userId, socket.id);
      console.log(`👤 User ${userId} registered with socket ${socket.id}`);
      io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    }
  });

  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, text, tempId } = data;

      const message = new Message({
        sender: senderId,
        receiver: receiverId,
        text
      });

      await message.save();

      const populatedMessage = await message.populate([
        { path: 'sender', select: 'username email' },
        { path: 'receiver', select: 'username email' }
      ]);

      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', populatedMessage);
      }

      socket.emit('messageSent', { tempId, message: populatedMessage });

    } catch (error) {
      console.error('❌ Socket message error:', error);
      socket.emit('messageError', { message: 'Failed to send message' });
    }
  });

  socket.on('typing', ({ senderId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userTyping', { userId: senderId });
    }
  });

  socket.on('stopTyping', ({ senderId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userStoppedTyping', { userId: senderId });
    }
  });

  /* ----------------------------- WEBRTC SIGNALING ----------------------------- */
  
  // Initiate a call
  socket.on('initiate-call', ({ to, from, callType, roomId }) => {
    console.log(`📞 Call initiated from ${from} to ${to}, type: ${callType}, room: ${roomId}`);
    
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      // Store call info
      activeCalls.set(roomId, {
        participants: [from, to],
        callType,
        initiator: from
      });
      
      io.to(receiverSocketId).emit('incoming-call', {
        from,
        callType,
        roomId
      });
    } else {
      socket.emit('call-error', { message: 'User is not online' });
    }
  });

  // Accept a call
  socket.on('accept-call', ({ to, from, roomId }) => {
    console.log(`✅ Call accepted by ${from}, notifying ${to}`);
    
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('call-accepted', {
        from,
        roomId
      });
    }
  });

  // Reject a call
  socket.on('reject-call', ({ to, from }) => {
    console.log(`❌ Call rejected by ${from}, notifying ${to}`);
    
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('call-rejected', { from });
    }
  });

  // End a call
  socket.on('end-call', ({ to, from }) => {
    console.log(`📞 Call ended by ${from}, notifying ${to}`);
    
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('call-ended', { from });
    }
    
    // Clean up active calls
    for (const [roomId, call] of activeCalls.entries()) {
      if (call.participants.includes(from)) {
        activeCalls.delete(roomId);
        break;
      }
    }
  });

  // Join a call room
  socket.on('join-call', ({ roomId, userId }) => {
    console.log(`👤 User ${userId} joining call room: ${roomId}`);
    socket.join(roomId);
    
    const call = activeCalls.get(roomId);
    if (call && !call.participants.includes(userId)) {
      call.participants.push(userId);
    }
    
    // Notify others in the room
    socket.to(roomId).emit('user-joined-call', { userId, roomId });
  });

  // Leave a call room
  socket.on('leave-call', ({ roomId, userId }) => {
    console.log(`👤 User ${userId} leaving call room: ${roomId}`);
    socket.leave(roomId);
    
    socket.to(roomId).emit('user-left-call', { userId });
    
    // Clean up if room is empty
    const call = activeCalls.get(roomId);
    if (call) {
      call.participants = call.participants.filter(id => id !== userId);
      if (call.participants.length === 0) {
        activeCalls.delete(roomId);
      }
    }
  });

  // WebRTC Offer
  socket.on('webrtc-offer', ({ offer, to, roomId }) => {
    console.log(`📨 WebRTC offer from ${socket.id} to ${to}`);
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('webrtc-offer', {
        offer,
        from: socket.userId,
        roomId
      });
    }
  });

  // WebRTC Answer
  socket.on('webrtc-answer', ({ answer, to, roomId }) => {
    console.log(`📨 WebRTC answer from ${socket.id} to ${to}`);
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('webrtc-answer', {
        answer,
        from: socket.userId,
        roomId
      });
    }
  });

  // ICE Candidates
  socket.on('ice-candidate', ({ candidate, to }) => {
    console.log(`🧊 ICE candidate from ${socket.id} to ${to}`);
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('ice-candidate', {
        candidate,
        from: socket.userId
      });
    }
  });

  socket.on('disconnect', () => {
    console.log('🔌 User disconnected:', socket.id);
    
    // Clean up user from online users
    for (const [userId, socketId] of onlineUsers.entries()) {
      if (socketId === socket.id) {
        onlineUsers.delete(userId);
        console.log(`👤 User ${userId} removed from online users`);
        
        // Clean up any active calls for this user
        for (const [roomId, call] of activeCalls.entries()) {
          if (call.participants.includes(userId)) {
            // Notify other participants
            call.participants.forEach(participantId => {
              if (participantId !== userId) {
                const participantSocketId = onlineUsers.get(participantId);
                if (participantSocketId) {
                  io.to(participantSocketId).emit('user-left-call', { userId });
                }
              }
            });
            
            // Remove user from call
            call.participants = call.participants.filter(id => id !== userId);
            if (call.participants.length === 0) {
              activeCalls.delete(roomId);
            }
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
      updateProfile: 'PUT /profile',
      users: 'GET /users',
      messages: 'GET /messages/:userId',
      sendMessage: 'POST /messages'
    }
  });
});

// Anonymous Signup Route
app.post('/anonymous-signup', async (req, res) => {
  try {
    let { username, gender, isAnonymous } = req.body;
    
    if (!username || !gender) {
      return res.status(400).json({ 
        message: 'Username and gender are required.',
        error: 'Username and gender are required.'
      });
    }

    if (username.length < 2) {
      return res.status(400).json({ 
        message: 'Username must be at least 2 characters long.',
        error: 'Username must be at least 2 characters long.'
      });
    }

    if (username.length > 20) {
      return res.status(400).json({ 
        message: 'Username must be less than 20 characters.',
        error: 'Username must be less than 20 characters.'
      });
    }

    // Check if username already exists and make it unique for anonymous users
    let finalUsername = username.trim();
    let existingUser = await User.findOne({ username: finalUsername });
    
    if (existingUser) {
      // Generate unique username by adding random numbers
      let attempts = 0;
      const maxAttempts = 10;
      
      while (existingUser && attempts < maxAttempts) {
        const randomSuffix = Math.floor(Math.random() * 10000);
        finalUsername = `${username.trim()}${randomSuffix}`;
        existingUser = await User.findOne({ username: finalUsername });
        attempts++;
      }
      
      // If still exists after max attempts, return error
      if (existingUser) {
        return res.status(409).json({ 
          message: 'Could not generate unique username. Please try a different name.',
          error: 'Could not generate unique username. Please try a different name.'
        });
      }
      
      console.log(`⚠️ Username ${username} existed, created unique username: ${finalUsername}`);
    }

    // Create anonymous user without email/password
    const user = new User({ 
      username: finalUsername, 
      gender,
      isAnonymous: true,
      tokenVersion: 0
      // Don't set email at all - leave it undefined
    });

    await user.save();
    console.log(`✅ Anonymous user created: ${user.username}`);

    // Generate token
    const token = generateToken(user._id, user.tokenVersion);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({ 
      message: 'Anonymous user created successfully!', 
      user: { 
        id: user._id,
        _id: user._id, 
        username: user.username, 
        gender: user.gender,
        isAnonymous: user.isAnonymous,
        token
      } 
    });
  } catch (error) {
    console.error('Anonymous signup error:', error);
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(409).json({ 
        message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists.`,
        error: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists.`
      });
    }
    res.status(500).json({ 
      message: 'Internal server error. Please try again later.',
      error: 'Internal server error. Please try again later.'
    });
  }
});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, gender } = req.body;
    
    if (!username || !email || !password || !gender) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ message: 'Username must be at least 3 characters long.' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ 
        message: existingUser.email === email ? 'Email already registered.' : 'Username already taken.' 
      });
    }

    const user = new User({ username, email, password, gender, tokenVersion: 0, isAnonymous: false });
    await user.save();

    res.status(201).json({ 
      message: 'User created successfully!', 
      user: { 
        id: user._id, 
        username, 
        email, 
        gender 
      } 
    });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(409).json({ 
        message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists.` 
      });
    }
    res.status(500).json({ message: 'Internal server error. Please try again later.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Prevent anonymous users from logging in with email/password
    if (user.isAnonymous) {
      return res.status(401).json({ message: 'This is an anonymous account. Cannot login with email.' });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    user.tokenVersion += 1;
    await user.save();

    console.log(`🔐 User ${user.username} logged in. New tokenVersion: ${user.tokenVersion}`);

    const token = generateToken(user._id, user.tokenVersion);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ 
      message: 'Login successful!', 
      user: { 
        id: user._id, 
        username: user.username, 
        email, 
        gender: user.gender,
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error. Please try again later.' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout successful!' });
});

app.get('/me', authenticateToken, async (req, res) => {
  console.log('✅ /me route hit by user:', req.userId);
  try {
    const user = await User.findById(req.userId).select('-password -tokenVersion');
    if (!user) {
      console.log('❌ User not found for ID:', req.userId);
      return res.status(404).json({ message: 'User not found.' });
    }

    console.log('✅ User found:', user.username);
    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

app.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { username, gender } = req.body;
    const userId = req.userId;

    if (username) {
      const existingUser = await User.findOne({ username, _id: { $ne: userId } });
      if (existingUser) {
        return res.status(409).json({ message: 'Username already taken.' });
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId, 
      { 
        ...(username && { username }), 
        ...(gender && { gender }) 
      }, 
      { 
        new: true, 
        runValidators: true 
      }
    ).select('-password -tokenVersion');

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({ 
      message: 'Profile updated successfully!', 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

/* ----------------------------- MESSAGE ROUTES ----------------------------- */

app.post('/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, text } = req.body;
    if (!receiverId || !text) {
      return res.status(400).json({ message: 'Receiver and text are required.' });
    }

    const message = new Message({
      sender: req.userId,
      receiver: receiverId,
      text
    });

    await message.save();

    const populatedMessage = await message.populate([
      { path: 'sender', select: 'username email' },
      { path: 'receiver', select: 'username email' }
    ]);

    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('receiveMessage', populatedMessage);
    }

    res.status(201).json(populatedMessage);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Failed to send message.' });
  }
});

app.get('/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const otherUserId = req.params.userId;

    const messages = await Message.find({
      $or: [
        { sender: req.userId, receiver: otherUserId },
        { sender: otherUserId, receiver: req.userId }
      ]
    })
      .sort({ createdAt: 1 })
      .populate('sender', 'username email')
      .populate('receiver', 'username email');

    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Failed to fetch messages.' });
  }
});

app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } }).select('_id username email gender');
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Failed to fetch users.' });
  }
});

app.get('/health', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStates = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
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
    activeCalls: activeCalls.size
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    message: 'Route not found', 
    path: req.originalUrl 
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ 
    message: 'Something went wrong!', 
    ...(process.env.NODE_ENV === 'development' && { error: err.message }) 
  });
});

/* ----------------------------- SERVER ----------------------------- */

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Client URL: ${process.env.CLIENT_URL || 'http://localhost:3000'}`);
  console.log(`🔑 JWT Secret: ${process.env.JWT_SECRET ? 'configured' : 'using default (INSECURE!)'}`);
  console.log(`📊 MongoDB URI: ${(process.env.MONGO_URI || process.env.MONGODB_URI) ? 'configured' : 'NOT CONFIGURED!'}`);
  console.log(`📞 WebRTC Signaling: ✅ ENABLED`);
});
