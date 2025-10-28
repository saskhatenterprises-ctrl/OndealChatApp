// server.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

app.use(express.json());
app.use(cookieParser());

/* ----------------------------- CORS ----------------------------- */
const allowedOrigins = (process.env.CLIENT_URL || "http://localhost:3000")
  .split(",")
  .map((o) => o.trim());

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) callback(null, true);
      else callback(new Error(`Not allowed by CORS: ${origin}`));
    },
    credentials: true,
  })
);

/* ----------------------------- SOCKET.IO ----------------------------- */
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

/* ----------------------------- DATABASE ----------------------------- */
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI || process.env.MONGODB_URI;
    if (!mongoURI) throw new Error("MONGO_URI not defined");
    const conn = await mongoose.connect(mongoURI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 15000,
    });
    console.log(`✅ MongoDB connected: ${conn.connection.host}/${conn.connection.name}`);
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
};
connectDB();

/* ----------------------------- SCHEMAS ----------------------------- */
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String },
  gender: {
    type: String,
    required: true,
    enum: ["male", "female", "other", "trans", "prefer-not-to-say"],
  },
  isAnonymous: { type: Boolean, default: false },
  tokenVersion: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || this.isAnonymous) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.model("User", userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model("Message", messageSchema);

/* ----------------------------- AUTH ----------------------------- */
const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-jwt-key-change-this-in-production";

const generateToken = (userId, tokenVersion) =>
  jwt.sign({ userId, tokenVersion }, JWT_SECRET, { expiresIn: "7d" });

const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.header("Authorization")?.replace("Bearer ", "");
    if (!token) return res.status(401).json({ message: "No token provided" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) return res.status(401).json({ message: "User not found" });
    if (decoded.tokenVersion !== user.tokenVersion)
      return res.status(401).json({ message: "Session invalidated" });

    req.userId = user._id;
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
};

/* ----------------------------- SOCKET VARIABLES ----------------------------- */
const onlineUsers = new Map();
const waitingUsers = new Map();
const activeRandomChats = new Map();
const randomChatSessions = new Map();

/* ----------------------------- SOCKET AUTH ----------------------------- */
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("Authentication required"));
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.userId;
    next();
  } catch (err) {
    next(new Error("Authentication error"));
  }
});

/* ----------------------------- SOCKET EVENTS ----------------------------- */
io.on("connection", (socket) => {
  console.log(`⚡ User connected: ${socket.userId} (${socket.id})`);
  onlineUsers.set(socket.userId, socket.id);
  io.emit("onlineUsers", Array.from(onlineUsers.keys()));

  /* ---------------- RANDOM CHAT ---------------- */
  socket.on("start-random-chat", async ({ userId }) => {
    try {
      if (!userId) return socket.emit("random-chat-error", { message: "User ID required" });

      if (activeRandomChats.has(userId))
        return socket.emit("random-chat-error", { message: "Already in a chat" });
      if (waitingUsers.has(userId))
        return socket.emit("random-chat-waiting", { waitingCount: waitingUsers.size });

      waitingUsers.set(userId, socket.id);
      socket.emit("random-chat-waiting", { waitingCount: waitingUsers.size });

      const availableUsers = Array.from(waitingUsers.keys()).filter(
        (id) => id !== userId && !activeRandomChats.has(id)
      );

      if (availableUsers.length > 0) {
        // ✅ Fixed: random pairing
        const randomIndex = Math.floor(Math.random() * availableUsers.length);
        const matchedUserId = availableUsers[randomIndex];

        const [currentUser, matchedUser] = await Promise.all([
          User.findById(userId).select("username gender _id"),
          User.findById(matchedUserId).select("username gender _id"),
        ]);

        waitingUsers.delete(userId);
        waitingUsers.delete(matchedUserId);

        activeRandomChats.set(userId, matchedUserId);
        activeRandomChats.set(matchedUserId, userId);

        const sessionId = `random-${Date.now()}`;
        randomChatSessions.set(sessionId, { participants: [userId, matchedUserId] });

        const matchedSocketId = onlineUsers.get(matchedUserId);
        socket.emit("random-match-found", matchedUser);
        if (matchedSocketId) io.to(matchedSocketId).emit("random-match-found", currentUser);

        console.log(`🎯 Random match: ${userId} ↔ ${matchedUserId}`);
      } else {
        console.log(`⏳ Waiting user: ${userId}`);
      }
    } catch (err) {
      console.error("start-random-chat error:", err);
      socket.emit("random-chat-error", { message: "Failed to start random chat" });
    }
  });

  socket.on("stop-random-chat", ({ userId }) => {
    if (!userId) return;
    waitingUsers.delete(userId);
    const partnerId = activeRandomChats.get(userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) io.to(partnerSocketId).emit("random-match-left");
      activeRandomChats.delete(userId);
      activeRandomChats.delete(partnerId);
    }
    socket.emit("random-chat-stopped");
  });

  /* ---------------- MESSAGING ---------------- */
  socket.on("sendMessage", async ({ senderId, receiverId, text, tempId }) => {
    try {
      if (!text || !receiverId) return;
      const msg = new Message({ sender: senderId, receiver: receiverId, text });
      await msg.save();
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) io.to(receiverSocketId).emit("receiveMessage", msg);
      socket.emit("messageSent", { tempId, message: msg });
    } catch (err) {
      console.error("sendMessage error:", err);
      socket.emit("messageError", { message: "Failed to send message" });
    }
  });

  /* ---------------- DISCONNECT ---------------- */
  socket.on("disconnect", () => {
    onlineUsers.delete(socket.userId);
    waitingUsers.delete(socket.userId);

    const partnerId = activeRandomChats.get(socket.userId);
    if (partnerId) {
      const partnerSocketId = onlineUsers.get(partnerId);
      if (partnerSocketId) io.to(partnerSocketId).emit("random-match-left");
      activeRandomChats.delete(partnerId);
      activeRandomChats.delete(socket.userId);
    }

    io.emit("onlineUsers", Array.from(onlineUsers.keys()));
    console.log(`❌ User disconnected: ${socket.userId}`);
  });
});

/* ----------------------------- ROUTES ----------------------------- */
app.get("/", (req, res) =>
  res.json({
    message: "Chat API is running 🚀",
    endpoints: {
      signup: "POST /signup",
      login: "POST /login",
      anonymousSignup: "POST /anonymous-signup",
      randomChatStats: "/random-chat/stats",
    },
  })
);

/* ----------------------------- SERVER START ----------------------------- */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Allowed Origins: ${allowedOrigins}`);
});
