/** @module authr-nedb */

var Datastore = require('nedb');
var moment = require('moment');
var bcrypt = require('bcrypt');
var crypto = require('crypto');

/**
 * Represents a new Adapter instance for nedb.
 * @class
 * @param {object} config - Authr config object
 */

function Adapter(config) {
  this.config = config;
  this.db = new Datastore();
}

/**
 * Dummy connection function. Just returns the callback, since in-memory nedb doesn't require loading a database
 * @function
 * @name connect
 * @param {Callback} callback - execute callback after connection
 * @return {Callback}
 */
Adapter.prototype.connect = function (callback) {
  return callback();
};

/**
 * Dummy disconnect function. Just returns the callback, since in-memory nedb doesn't require loading a database
 * @function
 * @name disconnect
 * @param {Callback} callback - execute callback after connection
 * @return {Callback}
 */
Adapter.prototype.disconnect = function (callback) {
  return callback();
};

/**
 * Passes the signup object to the adapter so the adapter utilities can access them
 * @function
 * @name signupConfig
 * @param {Object} - User object to be persisted to the database
 * @example
 * adapter.signUpConfig({account: {username: 'some_user', password: 'some_password'}});
 */
Adapter.prototype.signupConfig = function (signup) {
  this.signup = signup;
};

/**
 * Look up a key's value when given the path as a string mimicing dot-notation.
 * Used recreate the user object with the correct keys and proper nesting before inserting the document
 * This allows for customizing the user document structure as desired.
 * @function
 * @name getVal
 * @param {Object} obj - Object to query. Almost always the signup object
 * @param {String} str - String representation of path. E.g., 'some.nested.path' or 'top_level_path'
 * @return {*}
 * @example
 * // returns 'test_username'
 * this.getVal({account:{username:'test_username'}}, 'account.username')
 */
Adapter.prototype.getVal = function (obj, str) {
  return str.split(".").reduce(function (o, x) {
    return o[x];
  }, obj);
};

/**
 * Builds the query object eventually passed to nedb.
 * Used to build the query using the document structure specifed in the authr config
 * @function
 * @name buildQuery
 * @param {Object} query - Object to add a key/value to
 * @param {String} path - String representation of path. E.g., 'some.nested.path' or 'top_level_path'
 * @param {*} value - value to insert into the path param's location
 * @return {Object}
 * @example
 * // returns '{account:{username:'some_username', password:'some_password'}}'
 * this.getVal({account:{username:'some_username'}}, 'account.password', 'some_password');
 */
Adapter.prototype.buildQuery = function (query, path, value) {
  var obj = query;
  var schema = obj; // a moving reference to internal objects within obj
  var pList = path.split('.');
  var len = pList.length;
  for(var i = 0; i < len - 1; i++) {
    var elem = pList[i];
    if(!schema[elem]) schema[elem] = {};
    schema = schema[elem];
  }

  schema[pList[len - 1]] = value;
  return obj;
};

/**
 * Builds a simple query
 * @function
 * @name buildSimpleQuery
 * @param {String} key - The key to give the query
 * @param {*} value - The value to give
 * @return {Object}
 */
Adapter.prototype.buildSimpleQuery = function (key, value) {
  return JSON.parse('{"' + key + '":"' + value + '"}');
};

/**
 * Check to see if the username is taken
 * @function
 * @name isUsernameTaken
 * @param {Function} cb - Run callback when finished connecting
 * @return {Function}
 */
Adapter.prototype.isUsernameTaken = function (username, cb) {
  var self = this;
  var query = this.buildSimpleQuery(this.config.user.username, username);
  this.db.findOne(query, function (err, doc) {
    if(err) {
      throw err;
    }

    if(doc) {

      self.user = doc;
      
      return cb(true);
    } else {
      return cb(false);
    }

  });
};

/**
 * Check to make sure the credentials were supplied
 * @function
 * @name checkCredentials
 * @return {}
 */
Adapter.prototype.checkCredentials = function () {
  username = this.getVal(this.signup, this.config.user.username);
  password = this.getVal(this.signup, this.config.user.password);
  if(!username || !password) {
    return this.config.errmsg.un_and_pw_required;
  } else {
    return null;
  }
};

/**
 * Hashes the password using bcrypt and the settings specified in the authr config
 * @function
 * @name hash_password
 * @param {Callback} callback - run a callback when hashing is complete
 * @return {Callback}
 */
Adapter.prototype.hash_password = function (callback) {
  var password = this.getVal(this.signup, this.config.user.password);
  var self = this;
  bcrypt.genSalt(this.config.security.hash_salt_factor, function (err, salt) {
    if(err) {
      callback(err);
    } else {
      bcrypt.hash(password, salt, function (err, hash) {
        if(err) {
          throw err;
          //callback(err);
        } else {
          self.signup = self.buildQuery(self.signup, self.config.user.password, hash);
          callback(err, hash);
        }
      });
    }
  });
};

/**
 * Compare the supplied password with the stored hashed password
 * @function
 * @name comparePassword
 * @param {Callback} callback - execute callback after the comparison
 * @return {Callback}
 */
Adapter.prototype.comparePassword = function (supplied_password, callback) {

  var self = this;
  var db_pass = this.getVal(this.user, this.config.user.password);

  bcrypt.compare(supplied_password, db_pass, function (err, match) {

    if(match) {
      return callback(null, user);
    } else {

      if(self.config.security.max_failed_login_attempts) {
        self.incrementFailedLogins(function (err) {
          return callback(err);
        });
      } else {
        return callback(self.config.errmsg.password_incorrect);
      }
    }
  });
};

/**
 * Called after a failed login attempt. Either increment the number of failed login attempts and report the error or lock the account and report that.
 * @function
 * @name incrementFailedLogins
 * @param {Callback} callback - execute a callback after the function runs
 * @return {Callback}
 */
Adapter.prototype.incrementFailedLogins = function (callback) {
  var current_failed_logins = this.getVal(this.user, this.config.user.account_failed_attempts) + 1;
  var max_failed_attempts = this.config.security.max_failed_login_attempts;
  var query;
  var msg;
  var self = this;
  if(current_failed_logins >= max_failed_attempts) {
    this.lockUserAccount(function (err) {
      callback(err);
    });
  } else {
    this.user = this.buildQuery(this.user, this.config.user.account_failed_attempts, current_failed_logins);
    msg = this.config.errmsg.password_incorrect.replace('##i##', max_failed_attempts - current_failed_logins);
    errmsg = {
      err: msg,
      remaining_attempts: max_failed_attempts - current_failed_logins
    };
    query = this.buildSimpleQuery(this.config.user.username, this.getVal(this.user, this.config.user.username));
    this.db.update(query, this.user, function (err, doc) {
      if(err) {
        throw err;
      }
      if(!doc) {
        throw new Exception('Failed login attempts could not be incremented');
      }

      return callback(errmsg);
    });
  }
};

/**
 * Toggle a user's account as locked or unlocked
 * @function
 * @name toggleLock
 * @param {Callback} callback - execute a callback after the account is unlocked.
 * @return {Callback}
 */
Adapter.prototype.unlockUserAccount = function (callback) {
  this.user = this.buildQuery(this.user, this.config.user.account_locked, false);
  var query = this.buildSimpleQuery(this.config.user.username, this.getVal(this.user, this.config.user.username));
  this.db.update(query, this.user, function (err, docs) {
    if(err) {
      throw err;
    }
    if(!docs) {
      throw new Exception('No user updated');
    }
    callback();
  });
};

/**
 * Lock a user's account after specified number of login attempts
 * @function
 * @name lockUserAccount
 * @param {Callback} callback - execute a callback after the lock
 * @return {Callback}
 */
Adapter.prototype.lockUserAccount = function (callback) {
  var expires;
  var query;
  var errmsg = this.config.errmsg.account_locked.replace('##i##', this.config.security.lock_account_for_minutes);
  var self = this;
  expires = moment().add(this.config.security.lock_account_for_minutes, 'minutes');
  this.user = this.buildQuery(this.user, this.config.user.account_locked, true);
  this.user = this.buildQuery(this.user, this.config.user.account_locked_until, expires.toDate());
  query = this.buildSimpleQuery(this.config.user.username, this.getVal(this.user, this.config.user.username));
  this.db.update(query, this.user, function (err, doc) {
    if(err) {
      throw err;
    }

    if(!doc) {
      throw Err('Account should be locked but could not be');
    }
    errobj = {
      err: errmsg,
      lock_until: expires.toDate()
    };
    callback(errobj);
  });
};

/**
 * Checks to see if the user's failed attempts are expired. Resets them if they are.
 * @function
 * @name failedAttemptsExpired
 * @param {Callback} callback - execute a callback when the function is finished
 * @return {Callback}
 */
Adapter.prototype.failedAttemptsExpired = function (callback) {
  var now = moment();
  var last_failed_attempt = this.getVal(this.user, this.config.user.account_last_failed_attempt);
  var attempts_expire = moment(last_failed_attempt).add(this.config.security.reset_attempts_after_minutes, 'minutes');
  if(now.isAfter(attempts_expire)) {
    this.resetFailedLoginAttempts(function () {
      callback(null, true);
    });
  } else {
    return callback(null, false);
  }
};

/**
 * Reset failed login attempts
 * @function
 * @name resetFailedLoginAttempts
 * @param {Callback} - execute a callback after the attempts are reset
 * @return {Callback}
 */
Adapter.prototype.resetFailedLoginAttempts = function (callback) {
  this.user = this.buildQuery(this.user, this.config.user.account_failed_attempts, 0);
  var query = this.buildSimpleQuery(this.config.user.username, this.getVal(this.user, this.config.user.username));
  this.db.update(query, this.user, function (err, doc) {
    if(err) {
      throw err;
    }
    callback(doc);
  });
};

/**
 * Check to see if the account is locked.
 * @function
 * @name isAccountLocked
 * @return {Boolean}
 */
Adapter.prototype.isAccountLocked = function (callback) {
  var isLocked = this.getVal(this.user, this.config.user.account_locked);
  var unlocked_at;
  if(isLocked) {
    unlocked_at = this.getVal(this.user, this.config.user.account_locked_until);
    var now = moment();
    var expires = moment(unlocked_at);
    if(now.isAfter(expires)) {
      this.unlockUserAccount(function () {
        return callback(null, false);
      });
    } else {
      return callback({
        err: this.config.errmsg.account_locked,
        unlocked_at: unlocked_at
      });
    }
  } else {
    return callback(null, false);
  }

};

Adapter.prototype.isEmailVerified = function(){
 var isVerified = this.getVal(this.user, this.config.user.email_verified);
  return isVerified;
};

/**
 * Create email verification code using the username and current datetime.
 * Sets expiration to now + number of hours defined in authr config (config.security.email_verification_expiration_hours)
 * @function
 * @name doEmailVerification
 * @param {Object} obj - Object to modify
 * @param {Callback} callback - Run a callback when finished
 * @return {Callback}
 */
Adapter.prototype.doEmailVerification = function (obj, callback) {
  var now = moment().format("dddd, MMMM Do YYYY, h:mm:ss a");
  var username = this.getVal(obj, this.config.user.username);
  var hash = crypto.createHash('md5').update(username + now).digest('hex');
  obj = this.buildQuery(obj, this.config.user.email_verification_hash, hash);
  obj = this.buildQuery(obj, this.config.user.email_verification_hash_expires, moment().add(this.config.security.email_verification_expiration_hours, 'hours').toDate());
  obj = this.buildQuery(obj, this.config.user.email_verified, false);
  return callback(null, obj);
};

/**
 * Create account security defaults
 * @function
 * @name doEmailVerification
 * @param {Object} obj - object to add to
 */
Adapter.prototype.buildAccountSecurity = function (obj) {
  obj = this.buildQuery(obj, this.config.user.account_locked, false);
  obj = this.buildQuery(obj, this.config.user.account_locked_until, null);
  obj = this.buildQuery(obj, this.config.user.account_failed_attempts, 0);
  obj = this.buildQuery(obj, this.config.user.account_last_failed_attempt, null);
};

/**
 * Saves the user saved in this.signup. Callback returns any errors and the user, if successfully inserted
 * @function
 * @name saveUser
 * @param {Callback} callback - Run a callback after the user has been inserted
 * @return {Callback}
 */
Adapter.prototype.saveUser = function (callback) {
  this.db.insert(this.signup, function (err, doc) {
    return callback(err, doc);
  });
};

/**
 * Looks for user account using email verification token
 * @function
 * @name findVerificationToken
 * @param {String} token - verification token to look for
 * @param {Callback} callback - execute callback when account is found
 * @return {Callback}
 */
Adapter.prototype.findVerificationToken = function (token, callback) {
  var self = this;

  var query = this.buildSimpleQuery(this.config.user.email_verification_hash, token);

  this.db.findOne(query, function (err, user) {
    if(err) {
      throw err;
    }
    if(!user) {
      return callback(self.config.errmsg.token_not_found, null);
    } else {

      self.user = user;
      return callback(null, user);
    }
  });
};

/**
 * Check to see if the token is expired
 * @function
 * @name verificationExpired
 * @return {Boolean}
 */
Adapter.prototype.verificationExpired = function () {
  var now = moment();
  expr = this.getVal(this.user, this.config.user.email_verification_hash_expires);
  var expires = moment(expr);
  if(now.isAfter(expires)) {
    return true;
  } else {
    return false;
  }
};

/**
 * Verify email address in the datastore
 * @function
 * @name verifyEmailAddress
 * @param {Callback} callback - Execute a callback when done inserting
 * @return {Callback} callback
 */
Adapter.prototype.verifyEmailAddress = function (callback) {
  this.user = this.buildQuery(this.user, this.config.user.email_verified, true);
  var self = this;
  var username = this.getVal(this.user, this.config.user.username);
  var find_query = this.buildSimpleQuery(this.config.user.username, username);
  this.db.update(find_query, this.user, function (err, user) {
    if(err) {
      throw err;
    }
    
    callback(null, self.user);
  });
};

/**
 * Remove the collection. Mostly used for testing. Will probably find a use for it.
 * @function
 * @name resetCollection
 * @param {Callback} callback - Execute callback when finished dropping the collection
 * @return {Callback}
 */
Adapter.prototype.resetCollection = function (callback) {
  this.db.remove({}, {
    multi: true
  }, function (err) {
    callback(err);
  });
};

module.exports = Adapter;