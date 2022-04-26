// Routes for authenticating users
const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn, ensureAdmin } = require("../middleware/auth");
const User = require("../models/user");


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || ! password) {
      throw new ExpressError('Missing username and/or password.', 404);
    }

    const isAuthenticated = await User.authenticate(username, password);
  
    if (!isAuthenticated) {
      throw new ExpressError('Invalid credentials.', 400);
    }

    const token = jwt.sign({ username }, SECRET_KEY);
    User.updateLoginTimestamp(username);

    return res.json({ token });
    
  } catch (e) {
    return next(e);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;

    await User.register({ username, password, first_name, last_name, phone });

    const token = jwt.sign({ username }, SECRET_KEY);
    User.updateLoginTimestamp(username);
   
    return res.json({ token });

  } catch (e) {
    return next(e);
  }
});

module.exports = router;