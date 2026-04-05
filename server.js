import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import { Sequelize, DataTypes } from 'sequelize';
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

// ===== PostgreSQL Session Store =====
const PgSession = connectPgSimple(session);

app.use(
    session({
        store: new PgSession({
            conString: process.env.DATABASE_URL,
        }),
        secret: 'Secret333',
        name: 'sessionId',
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 1000 * 60 * 60,
            httpOnly: true,
            sameSite: 'lax',
        },
    })
);

// ===== PostgreSQL Database =====
const sequelize = new Sequelize(
    process.env.PGDATABASE,
    process.env.PGUSER,
    process.env.PGPASSWORD,
    {
        host: process.env.PGHOST,
        port: process.env.PGPORT,
        dialect: 'postgres',
        logging: false,
    }
);

// ===== Models =====
const User = sequelize.define('User', {
    firstName: DataTypes.STRING,
    lastName: DataTypes.STRING,
    email: { type: DataTypes.STRING, unique: true },
    password: DataTypes.STRING,
});

const Favorite = sequelize.define('Favorite', {
    user_email: DataTypes.STRING,
    event_name: DataTypes.STRING,
    event_date: DataTypes.STRING,
    event_location: DataTypes.STRING,
});

const Booking = sequelize.define('Booking', {
    user_email: DataTypes.STRING,
    activity_name: DataTypes.STRING,
    booking_date: DataTypes.STRING,
    num_people: DataTypes.INTEGER,
    booking_status: { type: DataTypes.STRING, defaultValue: 'Pending' },
});

const ContactMessage = sequelize.define('ContactMessage', {
    name: DataTypes.STRING,
    email: DataTypes.STRING,
    phone: DataTypes.STRING,
    message: DataTypes.TEXT,
});

const HegraFeedback = sequelize.define('HegraFeedback', {
    user_id: DataTypes.STRING,
    username: DataTypes.STRING,
    comment: DataTypes.TEXT,
});

// Sync tables
await sequelize.sync();

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
app.get('/login', (req, res) =>
    res.render('login', { data: {}, err_msg: null })
);

app.post('/login', async (req, res) => {
    const user = await User.findOne({ where: { email: req.body.email } });

    if (!user || user.password !== req.body.password) {
        return res.render('login', {
            data: req.body,
            err_msg: 'Invalid login',
        });
    }

    req.session.user = {
        loggedin: true,
        username: user.firstName,
        email: user.email,
    };

    res.redirect('/');
});

app.get('/signup', (req, res) =>
    res.render('signup', { data: {}, err_msg: null })
);

app.post('/signup', async (req, res) => {
    try {
        await User.create(req.body);
        res.redirect('/login');
    } catch {
        res.render('signup', { data: req.body, err_msg: 'Email exists' });
    }
});

// ===== FAVORITES =====
app.post('/api/toggle-like', checkLogin, async (req, res) => {
    const { eventName } = req.body;
    const email = req.session.user.email;

    const row = await Favorite.findOne({
        where: { user_email: email, event_name: eventName },
    });

    if (row) {
        await row.destroy();
        return res.json({ liked: false });
    }

    await Favorite.create({
        user_email: email,
        event_name: eventName,
    });

    res.json({ liked: true });
});

// ===== BOOKINGS =====
app.post('/api/save-booking', checkLogin, async (req, res) => {
    try {
        const { activityName, bookingDate, numPeople } = req.body;

        const result = await Booking.create({
            user_email: req.session.user.email,
            activity_name: activityName,
            booking_date: bookingDate,
            num_people: numPeople,
        });

        res.json({ success: true, id: result.id });
    } catch {
        res.json({ success: false });
    }
});

// ===== PAGES =====
app.get('/', (req, res) => res.render('homepage'));
app.get('/tours', (req, res) => res.render('tours'));
app.get('/contact', (req, res) => res.render('contact'));
app.get('/about', (req, res) => res.render('about'));

app.get('/profile', checkLogin, async (req, res) => {
    const email = req.session.user.email;

    const favorites = await Favorite.findAll({
        where: { user_email: email },
    });

    const bookings = await Booking.findAll({
        where: { user_email: email },
    });

    res.render('profile', {
        user: req.session.user,
        favorites,
        bookings,
    });
});

// ===== SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('Server running'));

