const LocalStrategy = require('passport-local').Strategy;
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');

function initialize(passport) {
    const authenticateUser = (email, password, done) => {
        pool.query(
            `SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(results.rows);

                if (results.rows.length > 0) {
                    const user = results.rows[0];
                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if (err) {
                            console.log(err);
                        }
                        if (isMatch) {
                            return done(null, user);
                        } else {
                            // Password is incorrect
                            return done(null, false, { message: "Password is incorrect" });
                        }
                    });
                } else {
                    // No user
                    return done(null, false, { message: "No user with that email address" });
                }
            }
        )
    }
    passport.use(
        new LocalStrategy(
            { usernameField: 'email',
              passwordField: 'password'
            }, 
            authenticateUser
        )
    );

    passport.serializeUser((user, done) => {
        // Store only the user's ID in the session
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
            if (err) {
                return done(err);
            }
            if (results.rows.length > 0) {
                return done(null, results.rows[0]); // Pass the entire user object
            } else {
                return done(null, null); // User not found
            }
        });
    });    
}

module.exports = initialize;