var User
    , _ =               require('underscore')
    , passport =        require('passport')
    , LocalStrategy =   require('passport-local').Strategy
    , TwitterStrategy = require('passport-twitter').Strategy
    , FacebookStrategy = require('passport-facebook').Strategy
    , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
    , LinkedInStrategy = require('passport-linkedin').Strategy
    , check =           require('validator').check
    , userRoles =       require('../../client/js/routingConfig').userRoles;

var firebase = require('firebase-admin');

// TODO(DEVELOPER): Change the two placeholders below.
// [START initialize]
// Initialize the app with a service account, granting admin privileges
var serviceAccount = require("/Users/amounir/Workspace/wod-bud1/angular-client-side-auth/wod-bud-firebase-adminsdk-hvyfn-ae973c6989.json");

firebase.initializeApp({
  credential: firebase.credential.cert(serviceAccount),
  databaseURL: 'https://wod-bud.firebaseio.com'
});
// [END initialize]



module.exports = {
    addUser: function(username, password, role, email, callback) {
        
        var user = {
            username:   username,
            email:      email,
            password:   password,
            role:       role
        };

        module.exports.addOrUpdateUserToDatabase(user);

        callback(null, user);
    },

    findOrCreateOauthUser: function(provider, providerId, displayName, email, accessToken) {
        var user = {
            username: displayName,
            email:    email,
            role: userRoles.user,
            provider: provider,
            accessToken: accessToken
        };
        module.exports.addOrUpdateUserToDatabase(user);
        return user;
    },

    addOrUpdateUserToDatabase: function(user) {
        existingUser = firebase.database().ref().child('users')
        .orderByChild("username")
        .equalTo(user.username)
        .once ( 'value', function(existingUser)
        {
            if ( existingUser.val() == null )
            {
                // Get a key for a new User.
                var newPostKey = firebase.database().ref().child('users').push().key;

                // Write the new post's data simultaneously in the posts list and the user's post list.
                var updates = {};
                updates['/users/' + newPostKey] = user;

                firebase.database().ref().update(updates);
            }
        })
    },

    findAll: function() {
        return firebase.database().ref().child('users')
        .orderByChild("username")
        .on('value', function(existingUser)
        {
            return existingUser.val();
        });
    },

    findByEmail: function(email) {
        return firebase.database().ref().child('users')
        .orderByChild("email")
        .equalTo(email)
        .once ( 'value', function(existingUser)
        {
            return existingUser.val();
        });
    },

    findByUsername: function(username) {
        return firebase.database().ref().child('users')
        .orderByChild("username")
        .equalTo(username)
        .once ( 'value', function(existingUser)
        {
            return existingUser.val();
        });
    },

    findByProviderId: function(provider, id) {
        return firebase.database().ref().child('users')
        .orderByChild("provider")
        .equalTo(id)
        .once ( 'value', function(existingUser)
        {
            return existingUser.val();
        });
    },

    validate: function(user) {
        check(user.username, 'Username must be 1-20 characters long').len(1, 20);
        check(user.password, 'Password must be 5-60 characters long').len(5, 60);
        check(user.username, 'Invalid username').not(/((([A-Za-z]{3,9}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)/);

        // TODO: Seems node-validator's isIn function doesn't handle Number arrays very well...
        // Till this is rectified Number arrays must be converted to string arrays
        // https://github.com/chriso/node-validator/issues/185
        var stringArr = _.map(_.values(userRoles), function(val) { return val.toString() });
        check(user.role, 'Invalid user role given').isIn(stringArr);
    },

    localStrategy: new LocalStrategy(
        function(username, password, done) {

            var user = module.exports.findByUsername(username);

            if(!user) {
                done(null, false, { message: 'Incorrect username.' });
            }
            else if(user.password != password) {
                done(null, false, { message: 'Incorrect username.' });
            }
            else {
                return done(null, user);
            }

        }
    ),

    twitterStrategy: function() {
        if(!process.env.TWITTER_CONSUMER_KEY)    throw new Error('A Twitter Consumer Key is required if you want to enable login via Twitter.');
        if(!process.env.TWITTER_CONSUMER_SECRET) throw new Error('A Twitter Consumer Secret is required if you want to enable login via Twitter.');

        return new TwitterStrategy({
            consumerKey: process.env.TWITTER_CONSUMER_KEY,
            consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
            callbackURL: process.env.TWITTER_CALLBACK_URL || 'http://localhost:8000/auth/twitter/callback'
        },
        function(token, tokenSecret, profile, done) {
            var user = module.exports.findOrCreateOauthUser(profile.provider, profile.id);
            done(null, user);
        });
    },

    facebookStrategy: function() {
        if(!process.env.FACEBOOK_APP_ID)     throw new Error('A Facebook App ID is required if you want to enable login via Facebook.');
        if(!process.env.FACEBOOK_APP_SECRET) throw new Error('A Facebook App Secret is required if you want to enable login via Facebook.');

        return new FacebookStrategy({
            clientID: process.env.FACEBOOK_APP_ID,
            clientSecret: process.env.FACEBOOK_APP_SECRET,
            callbackURL: process.env.FACEBOOK_CALLBACK_URL || "http://localhost:8000/auth/facebook/callback"
        },
        function(accessToken, refreshToken, profile, done) {
            var user = module.exports.findOrCreateOauthUser(profile.provider, profile.id);
            done(null, user);
        });
    },

    googleStrategy: function()
     {

        return new GoogleStrategy(
            {
                clientID: "666308033451-pb5cbttosgj7a1it8ards8mqna474ehl.apps.googleusercontent.com",
                clientSecret: "eI0VbO7LqF7u5dznLCQcZhU9",
                callbackURL: process.env.GOOGLE_RETURN_URL || "http://localhost:8000/auth/google/return"
            },
            function(accessToken, refreshToken, profile, done)
            {
                var user = module.exports.findOrCreateOauthUser(
                    profile.provider,
                    profile.id,
                    profile.displayName,
                    profile.emails[0].value,
                    accessToken);
                return done(null, user);
            }
        )
    },

    linkedInStrategy: function() {
        if(!process.env.LINKED_IN_KEY)     throw new Error('A LinkedIn App Key is required if you want to enable login via LinkedIn.');
        if(!process.env.LINKED_IN_SECRET) throw new Error('A LinkedIn App Secret is required if you want to enable login via LinkedIn.');

        return new LinkedInStrategy({
            consumerKey: process.env.LINKED_IN_KEY,
            consumerSecret: process.env.LINKED_IN_SECRET,
            callbackURL: process.env.LINKED_IN_CALLBACK_URL || "http://localhost:8000/auth/linkedin/callback"
          },
           function(token, tokenSecret, profile, done) {
            var user = module.exports.findOrCreateOauthUser('linkedin', profile.id);
            done(null,user); 
          }
        );
    },
    serializeUser: function(user, done) {
        done(null, user.id);
    },

    deserializeUser: function(id, done) {
        var user = module.exports.findById(id);

        if(user)    { done(null, user); }
        else        { done(null, false); }
    }
};