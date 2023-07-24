const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const GOOGLE_CLIENT_ID = '191118507891-1krpgr25j53jum8lakirnikuhclajer2.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:4500/google/callback",
    passReqToCallback: true
  },
  function(accessToken, refreshToken, profile, cb, profile, done) {
    return done(null, profile)

    // User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //   return cb(err, user);
    // });
  }
));

passport.serializeUser(function(user, done) {
    done(null, user);
})

passport.deserializeUser(function(user, done) {
    done(null, user);
});