import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { Sequelize, DataTypes } from 'sequelize';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== Middleware =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: 'Secret333',
    name: 'sessionId',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// ===== Database =====
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './ALULA.db',
    logging: false
});

const db = new Database('./ALULA.db');

// ===== Models =====
const User = sequelize.define('User', {
    firstName: DataTypes.STRING,
    lastName: DataTypes.STRING,
    email: { type: DataTypes.STRING, unique: true },
    password: DataTypes.STRING
});

await sequelize.sync();

// ===== Tables =====
db.exec(`
CREATE TABLE IF NOT EXISTS concert_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_name TEXT,
    seats TEXT,
    full_name TEXT,
    email TEXT,
    phone TEXT,
    total INTEGER,
    booking_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    event_name TEXT,
    event_date TEXT,
    event_location TEXT,
    liked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_email, event_name)
);

CREATE TABLE IF NOT EXISTS user_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    activity_name TEXT,
    booking_date TEXT,
    num_people INTEGER,
    booking_status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    phone TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS hegra_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    username TEXT,
    comment TEXT
);
`);

// ===== Middleware =====
app.use((req, res, next) => {
    res.locals.username = req.session.user?.username || null;
    res.locals.loggedIn = req.session.user?.loggedin || false;
    next();
});

function checkLogin(req, res, next) {
    if (req.session.user?.loggedin) return next();
    res.redirect('/login');
}

// ===== AUTH =====
app.get('/login', (req, res) => res.render('login', { data: {}, err_msg: null }));

app.post('/login', async (req, res) => {
    const user = await User.findOne({ where: { email: req.body.email } });

    if (!user || user.password !== req.body.password) {
        return res.render('login', { data: req.body, err_msg: "Invalid login" });
    }

    req.session.user = {
        loggedin: true,
        username: user.firstName,
        email: user.email
    };

    res.redirect('/');
});

app.get('/signup', (req, res) => res.render('signup', { data: {}, err_msg: null }));

app.post('/signup', async (req, res) => {
    try {
        await User.create(req.body);
        res.redirect('/login');
    } catch {
        res.render('signup', { data: req.body, err_msg: "Email exists" });
    }
});

// ===== FAVORITES =====
app.post('/api/toggle-like', checkLogin, (req, res) => {
    const { eventName } = req.body;
    const email = req.session.user.email;

    const row = db.prepare(
        "SELECT * FROM user_favorites WHERE user_email=? AND event_name=?"
    ).get(email, eventName);

    if (row) {
        db.prepare("DELETE FROM user_favorites WHERE id=?").run(row.id);
        return res.json({ liked: false });
    }

    db.prepare(
        "INSERT INTO user_favorites (user_email,event_name) VALUES (?,?)"
    ).run(email, eventName);

    res.json({ liked: true });
});

// ===== BOOKINGS =====
app.post('/api/save-booking', checkLogin, (req, res) => {
    try {
        const { activityName, bookingDate, numPeople } = req.body;

        const result = db.prepare(
            "INSERT INTO user_bookings (user_email,activity_name,booking_date,num_people) VALUES (?,?,?,?)"
        ).run(req.session.user.email, activityName, bookingDate, numPeople);

        res.json({ success: true, id: result.lastInsertRowid });
    } catch {
        res.json({ success: false });
    }
});

// ===== PAGES =====
app.get('/', (req, res) => res.render('homepage'));
app.get('/tours', (req, res) => res.render('tours'));
app.get('/contact', (req, res) => res.render('contact'));
app.get('/about', (req, res) => res.render('about'));

app.get('/profile', checkLogin, (req, res) => {
    const favorites = db.prepare(
        "SELECT * FROM user_favorites WHERE user_email=?"
    ).all(req.session.user.email);

    const bookings = db.prepare(
        "SELECT * FROM user_bookings WHERE user_email=?"
    ).all(req.session.user.email);

    res.render('profile', { user: req.session.user, favorites, bookings });
});

// ===== SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running"));