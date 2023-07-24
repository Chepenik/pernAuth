const express = require('express');
const app = express();
// const session = require('express-session');
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');
const initializePassport = require('./passportConfig');
initializePassport(passport);
// const ejs = require('ejs');
// const googleStrategy = require('./auth/google');
// const twitterStrategy = require('./auth/twitter');
// const linkedinStrategy = require('./auth/linkedin');
// require('./auth/google');

const PORT = process.env.PORT || 4500;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));

app.use(session({
        secret: 'secret',

        resave: false,

        saveUninitialized: false
    })
);

app.use(passport.initialize());

app.use(passport.session());

app.use(flash());

// function isLoggedIn(req, res, next) {
//     req.user ? next() : res.sendStatus(401);
// }

// app.use(session({ secret: 'cats' }));
// app.use(passport.initialize());
// app.use(passport.session());

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/users/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
        } else {
            req.flash('success_msg', "You have logged out");
            res.redirect('/users/login');
        }
    });
});

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
    if (!req.user) {
        res.redirect('/users/login');
    } else {
        res.render('dashboard', { user: req.user });
    }
});

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render('register', { errors: [] }); 
});

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render('login');
});

// app.get('/', (req, res) => {
//     res.send('<a href="/auth/google">Authenticate With Google</a>');
//     res.send('<a href="/auth/twitter">Authenticate With Twitter</a>');
//     res.send('<a href="/auth/linkedin">Authenticate With LinkedIn</a>');
// });

// app.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));
// app.get('/auth/twitter', passport.authenticate('twitter'));
// app.get('/auth/linkedin', passport.authenticate('linkedin'));

// app.get('/google/callback', passport.authenticate('google', { 
//         successRedirect: '/protected', 
//         failureRedirect: '/auth/failure' 
//     }),
// );
// app.get('/twitter/callback', passport.authenticate('twitter', { 
//         successRedirect: '/protected', 
//         failureRedirect: '/auth/failure' 
//     }),
// );
// app.get('/linkedin/callback', passport.authenticate('linkedin', { 
//         successRedirect: '/protected', 
//         failureRedirect: '/auth/failure' 
//     }),
// );

// app.get('/auth/failure', (req, res) => {
//     res.send('Failed to authenticate...');
// });

// app.get('/protected', isLoggedIn, (req, res) => {
//     res.send(`Hello ${req.user.displayName}`);
// });

// app.get('/logout', (req, res) => {
//     req.logout();
//     req.session.destroy();
//     res.send('BYE!!!');
// });

app.post('/users/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name,
        email,
        password,
        password2
    });

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: "Please enter all fields" });
    }

    if (password.length < 6) {
        errors.push({ message: "Password should be at least 6 characters" });
    } // <-- Close the first if statement block here

    if (password != password2) {
        errors.push({ message: "Passwords do not match" });
    }

    if (errors.length > 0) {
        res.render('register', { errors });
    } else {
        // Form validation has passed

        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM users
            WHERE email = $1`, 
            [email], 
            (err, results) => {
                if(err) {
                    throw err;
                }
                console.log(results.rows);

                if (results.rows.length > 0) {
                    errors.push({ message: 'Email already registered' });
                    res.render('register', { errors });
                } else {
                    pool.query(
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,
                        [name, email, hashedPassword], (err, results) => {
                            if(err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash('success_msg', "You are now registered. Please log in");
                            res.redirect('/users/login');
                        }
                    )
                }
            }
        )
    }
});

app.post('/users/login', passport.authenticate('local', {
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
}));

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/users/dashboard');
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/users/login');
}

app.listen(PORT, () => console.log(`Listening on: ${PORT}`));