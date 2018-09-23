const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const passport = require('passport');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local').Strategy;
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;

const UserModel = require('./models/users');
const secret = 'dgfghjhkl';

const router = express.Router();

mongoose.connect('', { useNewUrlParser: true} ).catch((err) => {
  // Handle any error that occurred in any of the previous
  // promises in the chain.
  console.log(err);
});

const app = express();
app.use(cors());



router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const hashCost = 10;

  try {
    const passwordHash = await bcrypt.hash(password, hashCost);

    const payload = {
      username: user.username,
      expires: Date.now() + parseInt(process.env.JWT_EXPIRATION_MS),
    };

    const token = jwt.sign(JSON.stringify(payload), keys.secret);
    const userDocument = new UserModel({ username, passwordHash });
    await userDocument.save(); // push for save

    res.status(200).send({ "username": username }, {"token": token});

  } catch (error) {
    res.status(400).send({
      error: 'req body should take the form { username, password }',
    });
  }
});

router.post('/login', (req, res) => {
  passport.authenticate(
    'local',
    { session: false },
    (error, user) => {

      if (error || !user) {
        res.status(400).json({ error });
      }

      /** This is what ends up in our JWT */
      const payload = {
        username: user.username,
        expires: Date.now() + parseInt(process.env.JWT_EXPIRATION_MS),
      };

      /** assigns payload to req.user */
      req.login(payload, {session: false}, (error) => {
        if (error) {
          res.status(400).send({ error });
        }

        /** generate a signed json web token and return it in the response */
        const token = jwt.sign(JSON.stringify(payload), keys.secret);

        /** assign our jwt to the cookie */
        res.cookie('jwt', jwt, { httpOnly: true, secure: true });
        res.status(200).send({ "username": username }, {"token": token});
      });
    },
  )(req, res);
});

router.get('/protected',
  passport.authenticate('jwt', {session: false}),
  (req, res) => {
    const { user } = req;

    res.status(200).send({ user });
  });


  passport.use(new LocalStrategy((username, password) =>{
    usernameField: username,
    passwordField: password,
  }, async (username, password, done) => {
    try {
      const userDocument = await UserModel.findOne({username: username}).exec();
      const passwordsMatch = await bcrypt.compare(password, userDocument.passwordHash);

      if (passwordsMatch) {
        return done(null, userDocument);
      } else {
        return done('Incorrect Username / Password');
      }
    } catch (error) {
      done(error);
    }
  }));

  passport.use(new JWTStrategy({
      jwtFromRequest: req => req.cookies.jwt,
      secretOrKey: secret,
    },
    (jwtPayload, done) => {
      if (jwtPayload.expires > Date.now()) {
        return done('jwt expired');
      }

      return done(null, jwtPayload);
    }
  ));


const PORT = process.env.PORT || 5000; // Heroku dynamic port
//pass a http.Server instance
app.listen(PORT);  //listen on port 80

console.log('Server listening on:', PORT);
