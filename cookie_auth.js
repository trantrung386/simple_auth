// cookie_auth.js
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// ---------------- MONGOOSE ----------------
mongoose.connect("mongodb://127.0.0.1:27017/sessionAuth")
  .then(() => console.log("✅ MongoDB connected to sessionAuth"))
  .catch(err => console.error(err));

// ---------------- USER SCHEMA ----------------
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String, // hash bằng bcryptjs
  role: { type: String, default: "user" }
});

const User = mongoose.model("User", userSchema);

// ---------------- SESSION STORE ----------------
app.use(session({
  secret: "mysecretkey", // đổi thành biến môi trường trong thực tế
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: "mongodb://127.0.0.1:27017/sessionAuth",
    collectionName: "sessions"
  }),
  cookie: { maxAge: 1000 * 60 * 5 } // 5 phút
}));

// ---------------- ROUTES ----------------

// Register
app.post("/auth/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (!username || !password) {
      return res.status(400).send("Username and password required");
    }

    // kiểm tra user tồn tại
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).send("User already exists");

    // hash password
    const hashed = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      username,
      password: hashed,
      role: role || "user"
    });

    res.status(201).send(`User ${newUser.username} registered!`);
  } catch (err) {
    res.status(500).send("Server error: " + err.message);
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(401).send("Invalid credentials");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send("Invalid credentials");

    // Lưu user vào session
    req.session.userId = user._id;
    req.session.role = user.role;

    res.send("Logged in successfully!");
  } catch (err) {
    res.status(500).send("Server error: " + err.message);
  }
});

// Profile (protected)
app.get("/auth/profile", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send("Not authenticated");
  }

  const user = await User.findById(req.session.userId);
  if (!user) return res.status(401).send("User not found");

  res.send(`Welcome ${user.username}, your role is ${user.role}`);
});

// Logout
app.post("/auth/logout", (req, res) => {
  const sid = req.sessionID; // lấy session ID hiện tại
  req.session.destroy(async err => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Error logging out");
    }
    // xóa thẳng trong MongoDB
    req.sessionStore.destroy(sid, err2 => {
      if (err2) console.error("Error removing from store:", err2);
    });

    res.clearCookie("connect.sid", { path: "/" });
    res.send("Logged out successfully!");
  });
});


// ---------------- START SERVER ----------------
app.listen(3001, () => console.log("🚀 Server running on http://localhost:3001"));
