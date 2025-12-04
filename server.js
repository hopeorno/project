import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
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

app.use(session({
    secret: 'Secret333',
    name: 'sessionId',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000*60*60 } // 1 hour
}));

// ===== Database =====
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './ALULA.db',
    logging: false
});

// ===== User Model =====
const User = sequelize.define('User', {
    firstName: { type: DataTypes.STRING, allowNull: false },
    lastName: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false }
});

// Sync DB
await sequelize.sync();

// ===== Middleware: Check Login =====
function checkLogin(req, res, next){
    if(req.session.user && req.session.user.loggedin) next();
    else res.redirect('/login');
}

// ===== Routes =====

// Login Page
app.get('/login', (req,res)=> res.render('login', { data:{}, err_msg:null }));

// Login Post
app.post('/login', async (req,res)=>{
    const { email, password } = req.body;

    if(!email || !password) 
        return res.render('login', { data:req.body, err_msg:"Please enter email & password" });

    const user = await User.findOne({ where: { email } });

    if(!user || user.password !== password) 
        return res.render('login', { data:req.body, err_msg:"Invalid email or password" });

    req.session.user = { loggedin: true, username: user.firstName, email: user.email };
    res.redirect('/');
});

// Signup Page
app.get('/signup', (req,res)=> res.render('signup', { data:{}, err_msg:null }));

// Signup Post
app.post('/signup', async(req,res)=>{
    const { firstName, lastName, email, password } = req.body;

    if(!firstName || !lastName || !email || !password)
        return res.render('signup', { data:req.body, err_msg:"All fields are required" });

    try{
        await User.create({ firstName, lastName, email, password });
        res.redirect('/login');
    }catch(err){
        res.render('signup', { 
            data:req.body, 
            err_msg: err.message.includes("UNIQUE") ? "Email already exists" : err.message 
        });
    }
});

// Homepage
app.get('/', checkLogin, (req,res)=> {
    res.render('homepage', { username: req.session.user.username });
});

// Profile Page
app.get('/profile', checkLogin, (req,res)=> res.render('profile', { user: req.session.user }));

// Customize Content
app.get('/favorites', checkLogin, (req,res)=> res.render('favorites'));

// Booking Page
app.get('/booking', checkLogin, (req,res)=> res.render('booking'));

// Events Page
app.get('/tours', checkLogin, (req,res)=> res.render('tours'));

// Contact Page
app.get('/contact', checkLogin, (req,res)=> res.render('contact'));

// Tourist Information Page
app.get('/about', checkLogin, (req,res)=> res.render('about'));

// Logout
app.get('/logout', (req,res)=>{
    req.session.destroy(()=> res.redirect('/login'));
});


// ===== Start Server =====
app.listen(3000, ()=> console.log('Server running at http://localhost:3000'));
