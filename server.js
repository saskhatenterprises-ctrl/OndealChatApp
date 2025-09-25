const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:3000')
  .split(',')   // allow multiple if provided like: "http://localhost:3000,https://ondeal-chat-app.vercel.app"
  .map(origin => origin.trim());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow server-to-server or curl
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`❌ Not allowed by CORS: ${origin}`));
    }
  },
  credentials: true
}));

// MongoDB connection with better error handling
const connectDB = async () => {
  try {
    // Use MONGO_URI consistently
    const mongoURI = process.env.MONGO_URI;
    
    if (!mongoURI) {
      throw new Error('MONGO_URI is not defined in environment variables');
    }

    console.log('🔄 Attempting to connect to MongoDB...');
    console.log('📍 Connection string format:', mongoURI.startsWith('mongodb+srv://') ? 'SRV' : 'Standard');
    
    // Mongoose connection options optimized for cloud deployment
    const options = {
      serverSelectionTimeoutMS: 10000, // Increased timeout for cloud
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4, skip trying IPv6
      maxPoolSize: 10,
      minPoolSize: 2,
        useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 15000, // 15 seconds
  socketTimeoutMS: 45000,
  maxPoolSize: 10,

    };

    const conn = await mongoose.connect(mongoURI, options);

    console.log(`✅ MongoDB Connected Successfully!`);
    console.log(`📂 Database: ${conn.connection.name}`);
    console.log(`🔗 Host: ${conn.connection.host}`);

    // Connection event listeners
    mongoose.connection.on('connected', () => {
      console.log('🔗 Mongoose reconnected to MongoDB');
    });

    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err.message);
      // Don't exit, let it try to reconnect
    });

    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ Mongoose disconnected from MongoDB');
    });

    // Handle app termination gracefully
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('🔒 MongoDB connection closed due to app termination');
      process.exit(0);
    });

  } catch (error) {
    console.error('❌ Database connection failed!');
    console.error('Error type:', error.name);
    console.error('Error message:', error.message);
    
    // Provide specific troubleshooting based on error type
    if (error.message.includes('ENOTFOUND') || error.message.includes('querySrv')) {
      console.error('🔍 DNS Resolution Error - Possible causes:');
      console.error('   1. Check if your MongoDB Atlas cluster is active');
      console.error('   2. Verify the cluster name in your connection string');
      console.error('   3. Ensure your connection string uses mongodb+srv:// format');
      console.error('   4. Check if you have internet connectivity');
    } else if (error.message.includes('authentication failed')) {
      console.error('🔐 Authentication Error - Check:');
      console.error('   1. Username and password are correct');
      console.error('   2. Password special characters are URL encoded');
      console.error('   3. User exists in MongoDB Atlas');
    } else if (error.message.includes('whitelist')) {
      console.error('🛡️ IP Whitelist Error - Add 0.0.0.0/0 in MongoDB Atlas Network Access');
    }
    
    // Don't exit immediately in production, wait and retry
    if (process.env.NODE_ENV === 'production') {
      console.log('⏳ Retrying connection in 10 seconds...');
      setTimeout(connectDB, 10000);
    } else {
      process.exit(1);
    }
  }
};

// Connect to database
connectDB();

/* ----------------------------- USER SCHEMA ----------------------------- */

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
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Hash password before saving
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

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

/* ----------------------------- AUTH MIDDLEWARE ----------------------------- */

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

if (!process.env.JWT_SECRET) {
  console.warn('⚠️ WARNING: Using default JWT_SECRET. Please set JWT_SECRET in your .env file for production!');
}

const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token.' });
  }
};

/* ----------------------------- ROUTES ----------------------------- */

// Root route for testing
app.get('/', (req, res) => {
  res.json({
    message: 'API is running!',
    endpoints: {
      health: '/health',
      signup: 'POST /signup',
      login: 'POST /login',
      logout: 'POST /logout',
      profile: 'GET /me',
      updateProfile: 'PUT /profile'
    }
  });
});

// Signup
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

    // Check for existing user
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ 
        message: existingUser.email === email ? 'Email already registered.' : 'Username already taken.' 
      });
    }

    // Create new user
    const user = new User({ username, email, password, gender });
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

// Login
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

    const token = generateToken(user._id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({ 
      message: 'Login successful!', 
      user: { 
        id: user._id, 
        username: user.username, 
        email, 
        gender: user.gender 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error. Please try again later.' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout successful!' });
});

// Get current user
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

// Update profile
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
    ).select('-password');

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

// Health check with detailed info
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
    mongoUri: process.env.MONGO_URI ? 'configured' : 'not configured'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    message: 'Route not found', 
    path: req.originalUrl 
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ 
    message: 'Something went wrong!', 
    ...(process.env.NODE_ENV === 'development' && { error: err.message }) 
  });
});

/* ----------------------------- SERVER ----------------------------- */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Client URL: ${process.env.CLIENT_URL || 'http://localhost:3000'}`);
  console.log(`🔑 JWT Secret: ${process.env.JWT_SECRET ? 'configured' : 'using default (INSECURE!)'}`);
  console.log(`📊 MongoDB URI: ${process.env.MONGO_URI ? 'configured' : 'NOT CONFIGURED!'}`);
});
