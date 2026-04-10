/**
 * FitPulse - Standalone Server
 * Serves both frontend (Chrome) and backend API
 * Uses SQLite — no PostgreSQL needed!
 */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Database Setup ───────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, "fitpulse.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    fitness_goal TEXT DEFAULT 'general_fitness',
    age INTEGER,
    weight REAL,
    height REAL,
    activity_level TEXT DEFAULT 'moderately_active',
    avatar_url TEXT,
    bio TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS workouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    workout_name TEXT NOT NULL,
    category TEXT DEFAULT 'strength',
    duration INTEGER DEFAULT 0,
    calories_burned INTEGER DEFAULT 0,
    exercises TEXT DEFAULT '[]',
    notes TEXT,
    completed_at TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    target_value REAL DEFAULT 0,
    current_value REAL DEFAULT 0,
    unit TEXT DEFAULT '',
    category TEXT DEFAULT 'fitness',
    deadline TEXT,
    completed INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    workouts_completed INTEGER DEFAULT 0,
    calories_burned INTEGER DEFAULT 0,
    minutes_active INTEGER DEFAULT 0,
    weight REAL,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ─── Auth Helpers ─────────────────────────────────────────────────────────────
function hashPassword(password) {
  return crypto.createHash("sha256").update(password + "fitpulse_salt").digest("hex");
}
function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}
function generateToken(userId) {
  return Buffer.from(`${userId}:${Date.now()}:${crypto.randomBytes(16).toString("hex")}`).toString("base64url");
}
function getUserIdFromToken(token) {
  try {
    const decoded = Buffer.from(token, "base64url").toString("utf8");
    return parseInt(decoded.split(":")[0]);
  } catch { return null; }
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// CORS for local dev
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post("/api/auth/register", (req, res) => {
  try {
    const { name, email, password, fitnessGoal, age, weight, height, activityLevel } = req.body;
    if (!name || !email || !password || !fitnessGoal) {
      return res.status(400).json({ error: "Missing fields", message: "name, email, password, fitnessGoal required" });
    }
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (existing) return res.status(409).json({ error: "Email exists", message: "An account with this email already exists" });

    const stmt = db.prepare(`
      INSERT INTO users (name, email, password_hash, fitness_goal, age, weight, height, activity_level)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(name, email, hashPassword(password), fitnessGoal, age || null, weight || null, height || null, activityLevel || "moderately_active");
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    const token = generateToken(user.id);
    return res.status(201).json({ token, user: formatUser(user) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing fields", message: "Email and password required" });
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: "Invalid credentials", message: "Email or password is incorrect" });
    }
    return res.json({ token: generateToken(user.id), user: formatUser(user) });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/forgot-password", (req, res) => {
  return res.json({ message: "If an account exists, a reset link has been sent." });
});

// ─── User Routes ──────────────────────────────────────────────────────────────
function formatUser(u) {
  return {
    id: u.id, name: u.name, email: u.email,
    fitnessGoal: u.fitness_goal, age: u.age,
    weight: u.weight, height: u.height,
    activityLevel: u.activity_level, avatarUrl: u.avatar_url,
    bio: u.bio, createdAt: u.created_at,
  };
}

app.get("/api/users/profile", (req, res) => {
  const userId = parseInt(req.query.userId);
  if (!userId) return res.status(400).json({ error: "userId required" });
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  if (!user) return res.status(404).json({ error: "Not found" });
  return res.json(formatUser(user));
});

app.put("/api/users/profile", (req, res) => {
  try {
    const { userId, name, age, weight, height, activityLevel, fitnessGoal, bio } = req.body;
    if (!userId) return res.status(400).json({ error: "userId required" });
    db.prepare(`
      UPDATE users SET name=COALESCE(?,name), age=COALESCE(?,age), weight=COALESCE(?,weight),
      height=COALESCE(?,height), activity_level=COALESCE(?,activity_level),
      fitness_goal=COALESCE(?,fitness_goal), bio=COALESCE(?,bio), updated_at=datetime('now')
      WHERE id=?
    `).run(name, age, weight, height, activityLevel, fitnessGoal, bio, userId);
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    return res.json(formatUser(user));
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/users/change-email", (req, res) => {
  try {
    const { userId, newEmail, password } = req.body;
    if (!userId || !newEmail || !password) return res.status(400).json({ error: "Missing fields" });
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) return res.status(404).json({ error: "Not found" });
    if (!verifyPassword(password, user.password_hash)) return res.status(401).json({ error: "Incorrect password", message: "Current password is incorrect" });
    const taken = db.prepare("SELECT id FROM users WHERE email = ? AND id != ?").get(newEmail, userId);
    if (taken) return res.status(409).json({ error: "Email taken", message: "This email is already in use" });
    db.prepare("UPDATE users SET email = ?, updated_at = datetime('now') WHERE id = ?").run(newEmail, userId);
    const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    return res.json({ id: updated.id, email: updated.email, name: updated.name });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/users/change-password", (req, res) => {
  try {
    const { userId, currentPassword, newPassword } = req.body;
    if (!userId || !currentPassword || !newPassword) return res.status(400).json({ error: "Missing fields" });
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) return res.status(404).json({ error: "Not found" });
    if (!verifyPassword(currentPassword, user.password_hash)) return res.status(401).json({ error: "Incorrect password", message: "Current password is incorrect" });
    if (newPassword.length < 6) return res.status(400).json({ error: "Weak password", message: "Password must be at least 6 characters" });
    db.prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?").run(hashPassword(newPassword), userId);
    return res.json({ message: "Password changed successfully" });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/users/stats", (req, res) => {
  try {
    const userId = parseInt(req.query.userId);
    if (!userId) return res.status(400).json({ error: "userId required" });
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    const workouts = db.prepare("SELECT * FROM workouts WHERE user_id = ?").all(userId);
    const totalWorkouts = workouts.length;
    const totalCaloriesBurned = workouts.reduce((s, w) => s + (w.calories_burned || 0), 0);
    const totalMinutes = workouts.reduce((s, w) => s + (w.duration || 0), 0);
    const weekStart = new Date(); weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    const thisWeekWorkouts = workouts.filter(w => w.completed_at && new Date(w.completed_at) >= weekStart);
    const thisWeekCalories = thisWeekWorkouts.reduce((s, w) => s + (w.calories_burned || 0), 0);
    let bmi = null, bmiCategory = null;
    if (user?.weight && user?.height) {
      const hm = user.height / 100;
      bmi = parseFloat((user.weight / (hm * hm)).toFixed(1));
      bmiCategory = bmi < 18.5 ? "Underweight" : bmi < 25 ? "Normal" : bmi < 30 ? "Overweight" : "Obese";
    }
    const progress = db.prepare("SELECT date FROM progress WHERE user_id = ? ORDER BY date DESC").all(userId);
    let currentStreak = 0, longestStreak = 0, streak = 0;
    const sortedDates = progress.map(p => p.date);
    for (let i = 0; i < sortedDates.length; i++) {
      const exp = new Date(); exp.setDate(exp.getDate() - i);
      const expStr = exp.toISOString().split("T")[0];
      if (sortedDates[i] === expStr) { streak++; if (i <= 1) currentStreak = streak; }
      else break;
    }
    longestStreak = Math.max(streak, longestStreak);
    return res.json({ totalWorkouts, totalCaloriesBurned, totalMinutes, currentStreak, longestStreak, thisWeekWorkouts: thisWeekWorkouts.length, thisWeekCalories, bmi, bmiCategory });
  } catch (err) { return res.status(500).json({ error: "Server error" }); }
});

// ─── Workout Routes ───────────────────────────────────────────────────────────
app.get("/api/workouts", (req, res) => {
  const userId = parseInt(req.query.userId);
  if (!userId) return res.status(400).json({ error: "userId required" });
  const rows = db.prepare("SELECT * FROM workouts WHERE user_id = ? ORDER BY completed_at DESC").all(userId);
  return res.json(rows.map(w => ({ ...w, exercises: JSON.parse(w.exercises || "[]"), userId: w.user_id, workoutName: w.workout_name, caloriesBurned: w.calories_burned, completedAt: w.completed_at, createdAt: w.created_at })));
});

app.post("/api/workouts", (req, res) => {
  try {
    const { userId, workoutName, category, duration, caloriesBurned, exercises, notes, completedAt } = req.body;
    if (!userId || !workoutName) return res.status(400).json({ error: "userId and workoutName required" });
    const result = db.prepare(`
      INSERT INTO workouts (user_id, workout_name, category, duration, calories_burned, exercises, notes, completed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(userId, workoutName, category || "strength", duration || 0, caloriesBurned || 0, JSON.stringify(exercises || []), notes || null, completedAt || new Date().toISOString());
    const row = db.prepare("SELECT * FROM workouts WHERE id = ?").get(result.lastInsertRowid);
    return res.status(201).json({ ...row, exercises: JSON.parse(row.exercises || "[]"), workoutName: row.workout_name, caloriesBurned: row.calories_burned, completedAt: row.completed_at });
  } catch (err) { return res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/workouts/:id", (req, res) => {
  db.prepare("DELETE FROM workouts WHERE id = ?").run(req.params.id);
  return res.json({ message: "Deleted" });
});

// ─── Exercise Library ─────────────────────────────────────────────────────────
const EXERCISES = [
  { id: 1, name: "Push-ups", category: "strength", muscleGroup: "Chest", equipment: "None", difficulty: "Beginner", sets: 3, reps: "12-15", caloriesPerMin: 7 },
  { id: 2, name: "Squats", category: "strength", muscleGroup: "Legs", equipment: "None", difficulty: "Beginner", sets: 4, reps: "15", caloriesPerMin: 8 },
  { id: 3, name: "Pull-ups", category: "strength", muscleGroup: "Back", equipment: "Pull-up bar", difficulty: "Intermediate", sets: 3, reps: "8-10", caloriesPerMin: 10 },
  { id: 4, name: "Deadlifts", category: "strength", muscleGroup: "Full Body", equipment: "Barbell", difficulty: "Advanced", sets: 4, reps: "6-8", caloriesPerMin: 9 },
  { id: 5, name: "Plank", category: "strength", muscleGroup: "Core", equipment: "None", difficulty: "Beginner", sets: 3, reps: "60s", caloriesPerMin: 5 },
  { id: 6, name: "Burpees", category: "hiit", muscleGroup: "Full Body", equipment: "None", difficulty: "Intermediate", sets: 4, reps: "10", caloriesPerMin: 12 },
  { id: 7, name: "Running", category: "cardio", muscleGroup: "Legs", equipment: "None", difficulty: "Beginner", sets: 1, reps: "30 min", caloriesPerMin: 11 },
  { id: 8, name: "Cycling", category: "cardio", muscleGroup: "Legs", equipment: "Bike", difficulty: "Beginner", sets: 1, reps: "45 min", caloriesPerMin: 9 },
  { id: 9, name: "Mountain Climbers", category: "hiit", muscleGroup: "Core", equipment: "None", difficulty: "Intermediate", sets: 3, reps: "20", caloriesPerMin: 11 },
  { id: 10, name: "Bench Press", category: "strength", muscleGroup: "Chest", equipment: "Barbell", difficulty: "Intermediate", sets: 4, reps: "8-10", caloriesPerMin: 8 },
  { id: 11, name: "Lunges", category: "strength", muscleGroup: "Legs", equipment: "None", difficulty: "Beginner", sets: 3, reps: "12 each", caloriesPerMin: 7 },
  { id: 12, name: "Yoga Flow", category: "flexibility", muscleGroup: "Full Body", equipment: "Mat", difficulty: "Beginner", sets: 1, reps: "40 min", caloriesPerMin: 4 },
  { id: 13, name: "Jump Rope", category: "cardio", muscleGroup: "Full Body", equipment: "Jump rope", difficulty: "Beginner", sets: 3, reps: "2 min", caloriesPerMin: 13 },
  { id: 14, name: "Dumbbell Rows", category: "strength", muscleGroup: "Back", equipment: "Dumbbell", difficulty: "Beginner", sets: 3, reps: "12", caloriesPerMin: 7 },
  { id: 15, name: "Box Jumps", category: "hiit", muscleGroup: "Legs", equipment: "Box", difficulty: "Intermediate", sets: 4, reps: "8", caloriesPerMin: 12 },
];

app.get("/api/exercises", (req, res) => {
  const { category, search } = req.query;
  let results = EXERCISES;
  if (category && category !== "All") results = results.filter(e => e.category.toLowerCase() === category.toLowerCase());
  if (search) results = results.filter(e => e.name.toLowerCase().includes(search.toLowerCase()) || e.muscleGroup.toLowerCase().includes(search.toLowerCase()));
  return res.json(results);
});

// ─── Workout Plans ────────────────────────────────────────────────────────────
const PLANS = [
  { id: 1, name: "Beginner Full Body", duration: 4, level: "Beginner", goal: "general_fitness", description: "Perfect starting point for beginners", exercises: EXERCISES.slice(0, 5) },
  { id: 2, name: "HIIT Burn", duration: 6, level: "Intermediate", goal: "weight_loss", description: "High intensity intervals for maximum fat burn", exercises: [EXERCISES[5], EXERCISES[8], EXERCISES[6], EXERCISES[12]] },
  { id: 3, name: "Strength Builder", duration: 8, level: "Advanced", goal: "muscle_gain", description: "Build serious strength and muscle mass", exercises: [EXERCISES[1], EXERCISES[3], EXERCISES[2], EXERCISES[9]] },
  { id: 4, name: "Cardio Endurance", duration: 6, level: "Intermediate", goal: "endurance", description: "Boost your cardiovascular endurance", exercises: [EXERCISES[6], EXERCISES[7], EXERCISES[12], EXERCISES[8]] },
  { id: 5, name: "Flexibility & Yoga", duration: 4, level: "Beginner", goal: "flexibility", description: "Improve flexibility and mindfulness", exercises: [EXERCISES[11], EXERCISES[4]] },
];

app.get("/api/workouts/plans", (req, res) => res.json(PLANS));

// ─── Progress Routes ──────────────────────────────────────────────────────────
app.get("/api/progress/summary", (req, res) => {
  const userId = parseInt(req.query.userId);
  const days = parseInt(req.query.days) || 7;
  if (!userId) return res.status(400).json({ error: "userId required" });
  const rows = db.prepare("SELECT * FROM progress WHERE user_id = ? ORDER BY date DESC LIMIT ?").all(userId, days);
  return res.json(rows.map(r => ({ ...r, userId: r.user_id, workoutsCompleted: r.workouts_completed, caloriesBurned: r.calories_burned, minutesActive: r.minutes_active })));
});

app.post("/api/progress", (req, res) => {
  try {
    const { userId, date, workoutsCompleted, caloriesBurned, minutesActive, weight, notes } = req.body;
    if (!userId) return res.status(400).json({ error: "userId required" });
    const existing = db.prepare("SELECT id FROM progress WHERE user_id = ? AND date = ?").get(userId, date);
    if (existing) {
      db.prepare("UPDATE progress SET workouts_completed=?, calories_burned=?, minutes_active=?, weight=? WHERE id=?")
        .run(workoutsCompleted || 0, caloriesBurned || 0, minutesActive || 0, weight || null, existing.id);
      return res.json(db.prepare("SELECT * FROM progress WHERE id = ?").get(existing.id));
    }
    const result = db.prepare("INSERT INTO progress (user_id, date, workouts_completed, calories_burned, minutes_active, weight, notes) VALUES (?,?,?,?,?,?,?)").run(userId, date, workoutsCompleted || 0, caloriesBurned || 0, minutesActive || 0, weight || null, notes || null);
    const row = db.prepare("SELECT * FROM progress WHERE id = ?").get(result.lastInsertRowid);
    return res.status(201).json({ ...row, userId: row.user_id, workoutsCompleted: row.workouts_completed, caloriesBurned: row.calories_burned, minutesActive: row.minutes_active });
  } catch (err) { return res.status(500).json({ error: "Server error" }); }
});

// ─── Goals Routes ─────────────────────────────────────────────────────────────
app.get("/api/goals", (req, res) => {
  const userId = parseInt(req.query.userId);
  if (!userId) return res.status(400).json({ error: "userId required" });
  const rows = db.prepare("SELECT * FROM goals WHERE user_id = ? ORDER BY created_at DESC").all(userId);
  return res.json(rows.map(g => ({ ...g, userId: g.user_id, targetValue: g.target_value, currentValue: g.current_value })));
});

app.post("/api/goals", (req, res) => {
  try {
    const { userId, title, targetValue, currentValue, unit, category, deadline } = req.body;
    if (!userId || !title) return res.status(400).json({ error: "userId and title required" });
    const result = db.prepare("INSERT INTO goals (user_id, title, target_value, current_value, unit, category, deadline) VALUES (?,?,?,?,?,?,?)").run(userId, title, targetValue || 0, currentValue || 0, unit || "", category || "fitness", deadline || null);
    const row = db.prepare("SELECT * FROM goals WHERE id = ?").get(result.lastInsertRowid);
    return res.status(201).json({ ...row, userId: row.user_id, targetValue: row.target_value, currentValue: row.current_value });
  } catch (err) { return res.status(500).json({ error: "Server error" }); }
});

app.put("/api/goals/:id", (req, res) => {
  const { currentValue, completed } = req.body;
  db.prepare("UPDATE goals SET current_value = ?, completed = ? WHERE id = ?").run(currentValue, completed ? 1 : 0, req.params.id);
  const row = db.prepare("SELECT * FROM goals WHERE id = ?").get(req.params.id);
  return res.json({ ...row, userId: row.user_id, targetValue: row.target_value, currentValue: row.current_value });
});

app.delete("/api/goals/:id", (req, res) => {
  db.prepare("DELETE FROM goals WHERE id = ?").run(req.params.id);
  return res.json({ message: "Deleted" });
});

// ─── Achievements ─────────────────────────────────────────────────────────────
app.get("/api/achievements", (req, res) => res.json([]));

// ─── Serve frontend for all other routes (SPA) ───────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── Seed Demo Data ───────────────────────────────────────────────────────────
function seedDemo() {
  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get("demo@fitpulse.app");
  if (exists) return;
  const r = db.prepare("INSERT INTO users (name, email, password_hash, fitness_goal, age, weight, height, activity_level) VALUES (?,?,?,?,?,?,?,?)")
    .run("Alex Johnson", "demo@fitpulse.app", hashPassword("demo123"), "muscle_gain", 28, 75, 178, "moderately_active");
  const uid = r.lastInsertRowid;
  const workouts = [
    ["Morning HIIT", "cardio", 22, 310], ["Upper Body Strength", "strength", 38, 285],
    ["Leg Day", "strength", 45, 420], ["Core Blast", "strength", 18, 160],
    ["Full Body HIIT", "hiit", 30, 380], ["Yoga Flow", "flexibility", 40, 140],
  ];
  workouts.forEach(([name, cat, dur, cal], i) => {
    const d = new Date(); d.setDate(d.getDate() - i * 2);
    db.prepare("INSERT INTO workouts (user_id, workout_name, category, duration, calories_burned, exercises, completed_at) VALUES (?,?,?,?,?,?,?)")
      .run(uid, name, cat, dur, cal, "[]", d.toISOString());
  });
  [
    ["Run 100km this month", 100, 34, "km", "cardio"],
    ["Lose 5kg", 5, 2.3, "kg", "weight"],
    ["Complete 20 workouts", 20, 6, "workouts", "fitness"],
  ].forEach(([title, tgt, cur, unit, cat]) => {
    db.prepare("INSERT INTO goals (user_id, title, target_value, current_value, unit, category) VALUES (?,?,?,?,?,?)").run(uid, title, tgt, cur, unit, cat);
  });
  for (let i = 0; i < 7; i++) {
    const d = new Date(); d.setDate(d.getDate() - i);
    db.prepare("INSERT INTO progress (user_id, date, workouts_completed, calories_burned, minutes_active, weight) VALUES (?,?,?,?,?,?)")
      .run(uid, d.toISOString().split("T")[0], i % 2 === 0 ? 1 : 0, i % 2 === 0 ? 250 + i * 20 : 0, i % 2 === 0 ? 30 + i * 5 : 0, 75 - i * 0.1);
  }
  console.log("   Demo account created: demo@fitpulse.app / demo123");
}

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  seedDemo();
  console.log(`\n  ====================================`);
  console.log(`   FitPulse is RUNNING!`);
  console.log(`  ====================================`);
  console.log(`   Open Chrome: http://localhost:${PORT}`);
  console.log(`   Demo login:  demo@fitpulse.app`);
  console.log(`   Password:    demo123`);
  console.log(`  ====================================\n`);
});
