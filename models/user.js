/** User class for message.ly */
const { BCRYPT_WORK_FACTOR } = require('../config');
const db = require('../db');
const bcrypt = require("bcrypt");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    
    // check if username already exists
    const usernameResult = await db.query(`
      SELECT username
      FROM users
      WHERE username = $1
    `, [username]);

    if (usernameResult.rows.length) {
      const err = new Error(`Username ${username} is taken.`);
      err.status = 400;
      throw err;
    }
    
     // add user to db
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(`
      INSERT INTO users
      (username, password, first_name, last_name, phone, join_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp)
      RETURNING username, password, first_name, last_name, phone
    `, [username, hashedPassword, first_name, last_name, phone]);

    const user = result.rows[0];

    if (user === undefined) {
      const err = new Error('Could not register user.');
      err.status = 400;
      throw err;
    }

    return user;
  }


  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(`
      SELECT password
      FROM users
      WHERE username = $1
    `, [username]);

    const user = result.rows[0];

    // if user exists and password is valid, authenticate user
    return user && await bcrypt.compare(password, user.password);
   
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 

    const result = await db.query(`
      UPDATE users
      SET last_login_at = current_timestamp
      WHERE username = $1
      RETURNING username
    `, [username]);

    if (result.rows[0] === undefined) {
      const err = new Error('Could not update last login for user ' + username);
      err.status = 400;
      throw err;
    }
    
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const result = await db.query(`
      SELECT username, first_name, last_name, phone
      FROM users
    `)

    const users = result.rows;

    if (!users.length) {
      const err = new Error('Could not fetch users');
      err.status = 400;
      throw err;
    }

    return users;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`
      SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1
    `, [username]);

    const user = result.rows[0];

    if (user === undefined) {
      const err = new Error('Could not find user with username ' + username);
      err.status = 404;
      throw err;
    }

    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 

    const messagesResult = await db.query(`
      SELECT m.id, u.username AS to_user, m.body, m.sent_at, m.read_at
      FROM messages AS m
      INNER JOIN users AS u
      ON m.to_username = u.username
      WHERE from_username = $1
    `, [username]);

    const messages = await Promise.all(messagesResult.rows.map(async (m) => {
      const to_userResult = await db.query(`
        SELECT username, first_name, last_name, phone
        FROM users
        WHERE username = $1
      `, [m.to_user]);

      m.to_user = to_userResult.rows[0];

      return m;
    }));

    if (!messages.length) {
      const err = new Error('Could not fetch messages from username ' + username);
      err.status = 404;
      throw err;
    }
    
    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 

    const messagesResult = await db.query(`
      SELECT m.id, u.username AS from_user, m.body, m.sent_at, m.read_at
      FROM messages AS m
      INNER JOIN users AS u
      ON m.from_username = u.username
      WHERE to_username = $1
    `, [username]);

    const messages = await Promise.all(messagesResult.rows.map(async (m) => {
      const from_userResult = await db.query(`
        SELECT username, first_name, last_name, phone
        FROM users
        WHERE username = $1
      `, [m.from_user]);

      m.from_user = from_userResult.rows[0];

      return m;
    }));

    if (!messages.length) {
      const err = new Error('Could not fetch messages received by username ' + username);
      err.status = 404;
      throw err;
    }
    
    return messages;
  }
}


module.exports = User;