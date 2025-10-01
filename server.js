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

// Parse client URLs from environment variable
const clientUrls = process.env.CLIENT_URL ? process.env.CLIENT_URL.split(',') : ['http://localhost:3000'];

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: clientUrls,          
  credentials: true
}));

// MongoDB connection - USING YOUR EXACT MONGO_URI
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ondealChatApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected Successfully!'))
.catch((err) => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true, 
    minlength: 3, 
    maxlength: 30 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true, 
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email'] 
  },
  password: { 
    type: String, 
    required: true, 
    minlength: 6 
  },
  gender: { 
    type: String, 
    required: true, 
    enum: ['male', 'female', 'other', 'trans', 'prefer-not-to-say'] 
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  text: {
    type: String,
    required: true,
    trim: true,
    maxlength: 1000
  },
  isRead: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

messageSchema.index({ sender: 1, receiver: 1, createdAt: -1 });

const Message = mongoose.model('Message', messageSchema);

// JWT Secret - USING YOUR EXACT JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET;

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(403).json({ message: 'Invalid token.' });
  }
};

// Socket.io setup
const io = new Server(server, {
  cors: {
    origin: clientUrls,
    credentials: true
  }
});

// Store online users
const onlineUsers = new Map();

// Socket.io authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication error: No token provided'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Socket authentication error:', error);
    next(new Error('Authentication error: Invalid token'));
  }
});

// Socket.io connection handling
io.on('connection', async (socket) => {
  console.log('🔗 User connected:', socket.userId);
  
  try {
    // Add user to online users
    const user = await User.findById(socket.userId);
    if (user) {
      onlineUsers.set(socket.userId.toString(), {
        userId: socket.userId.toString(),
        username: user.username,
        socketId: socket.id
      });
      
      // Update user online status
      await User.findByIdAndUpdate(socket.userId, { 
        isOnline: true,
        lastSeen: new Date()
      });

      // Broadcast online users to all clients
      io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    }

    // Register user with their socket ID
    socket.emit('connected', { message: 'Connected to chat server' });

    // Handle user registration (for specific room joining)
    socket.on('register', (userId) => {
      socket.join(userId);
      console.log(`User ${userId} registered with socket ${socket.id}`);
    });

    // Handle sending messages
    socket.on('sendMessage', async (data) => {
      try {
        const { senderId, receiverId, text, tempId } = data;
        
        console.log('📨 New message:', { senderId, receiverId, text: text.substring(0, 50) });

        // Create and save message
        const message = new Message({
          sender: senderId,
          receiver: receiverId,
          text: text
        });

        await message.save();

        // Populate sender info
        await message.populate('sender', 'username email');
        await message.populate('receiver', 'username email');

        // Send to receiver if online
        const receiverSocket = onlineUsers.get(receiverId);
        if (receiverSocket) {
          io.to(receiverSocket.socketId).emit('receiveMessage', message);
        }

        // Send acknowledgment to sender with tempId for UI update
        socket.emit('messageSent', {
          tempId,
          message: message
        });

        console.log('✅ Message saved and delivered');

      } catch (error) {
        console.error('Error sending message:', error);
        socket.emit('messageError', { 
          tempId: data.tempId,
          error: 'Failed to send message' 
        });
      }
    });

    // Handle typing indicators
    socket.on('typing', (data) => {
      const { senderId, receiverId } = data;
      const receiverSocket = onlineUsers.get(receiverId);
      if (receiverSocket) {
        io.to(receiverSocket.socketId).emit('userTyping', { userId: senderId });
      }
    });

    socket.on('stopTyping', (data) => {
      const { senderId, receiverId } = data;
      const receiverSocket = onlineUsers.get(receiverId);
      if (receiverSocket) {
        io.to(receiverSocket.socketId).emit('userStoppedTyping', { userId: senderId });
      }
    });

    // Handle disconnect
    socket.on('disconnect', async () => {
      console.log('🔌 User disconnected:', socket.userId);
      
      // Remove from online users
      onlineUsers.delete(socket.userId.toString());
      
      // Update user offline status
      await User.findByIdAndUpdate(socket.userId, { 
        isOnline: false,
        lastSeen: new Date()
      });

      // Broadcast updated online users
      io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    });

  } catch (error) {
    console.error('Socket connection error:', error);
  }
});

// Routes

// Signup Route
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, gender } = req.body;

    // Validation
    if (!username || !email || !password || !gender) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }
    
    if (username.length < 3) {
      return res.status(400).json({ message: 'Username must be at least 3 characters long.' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(409).json({ 
          message: 'Email already registered.' 
        });
      } else {
        return res.status(409).json({ 
          message: 'Username already taken.' 
        });
      }
    }

    // Create new user
    const user = new User({
      username,
      email,
      password,
      gender
    });

    await user.save();

    // Generate token for auto-login after signup
    const token = generateToken(user._id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({ 
      message: 'User created successfully!', 
      user: { 
        _id: user._id, 
        username, 
        email, 
        gender 
      },
      token: token
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

// Login Route
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

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Generate token
    const token = generateToken(user._id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      message: 'Login successful!',
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        gender: user.gender
      },
      token: token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error. Please try again later.' });
  }
});

// Get all users (except current user)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } })
      .select('username email gender isOnline lastSeen')
      .sort({ username: 1 });
    
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

// Get messages between two users
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const otherUserId = req.params.userId;
    const currentUserId = req.userId;

    const messages = await Message.find({
      $or: [
        { sender: currentUserId, receiver: otherUserId },
        { sender: otherUserId, receiver: currentUserId }
      ]
    })
    .populate('sender', 'username email')
    .populate('receiver', 'username email')
    .sort({ createdAt: 1 });

    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

// Logout Route
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout successful!' });
});

// Get current user (protected route)
app.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    onlineUsers: onlineUsers.size,
    environment: process.env.NODE_ENV
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    message: 'Route not found' 
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Global error handler:', err);
  res.status(500).json({ 
    message: 'Internal server error' 
  });
});

// Start server - USING YOUR EXACT PORT
const PORT = process.env.PORT || 5000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
  console.log(`🔌 Socket.IO enabled`);
  console.log(`📂 Database: ondealChatApp`);
  console.log(`✅ MongoDB Connected Successfully!`);
});
