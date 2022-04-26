// Message routes
const express = require("express");
const router = new express.Router();
const Message = require('../models/message');
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', ensureCorrectUser, async (req, res, next) => {
  try {

    const { id } = req.params;
    const message = await Message.get(id);

    return res.json({ message });

  } catch (e) {
    return next(new ExpressError(e));
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post('/', ensureCorrectUser, async (req, res, next) => {
  try {

    const { username: from_username } = jwt.decode(req.body._token);
    const { to_username, body } = req.body;
    const message = await Message.create(from_username, to_username, body);

    return res.json({ message });

  } catch (e) {
    return next(new ExpressError(e));
  }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post('/:id', ensureCorrectUser, async (req, res, next) => {
  try {

    const { id } = req.params;

    const message = await Message.markRead(id);

    return res.json({ message });
    
  } catch (e) {
    return next(new ExpressError(e));
  }
});

module.exports = router;