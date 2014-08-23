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

// PUBLIC API METHODS
// ------------------


/**
 * Dummy connection function. Connect is a required method, but connecting isn't required in nedb. Just returns the callback
 * @param {Function} callback - handles response
 */
Adapter.prototype.connect = function (callback) {
  return callback();
};

/**
 * Connection callback
 * @callback Adapter~connectCallback
 */

/**
 * Dummy disconnect function. Disconnect is a required method, but it is not required in nedb. Just returns a callback.
 * @param {Function} callback - execute callback after connection
 */
Adapter.prototype.disconnect = function (callback) {
  return callback();
};

/**
 * Check to see if a value exists in the database. Supply the source object and the path to the value to be checked
 * @param {Object} object - object to query
 * @path {Object}  path - path to the value
 * @param {isValueTakenCallback} callback - Run a callback after checking the database
 */
Adapter.prototype.isValueTaken = function (object, path, callback) {
  var self = this;
  var val = this.getVal(object, path);
  if(val){
    val.toLowerCase();
  }
  var query = this.buildSimpleQuery(path, val);
  this.db.findOne(query, function (err, doc) {
    if(err) {
      callback(err, null);
    }

    if(doc) {
      callback(null, doc);
    } else {
      return callback(null, false);
    }

  });
};

/**
 * Handles response for isValueTaken method
 * @callback isValueTakenCallback
 * @param {String} err - error message, if any
 * @param {Boolean|Object} doc - Document, if found, or false if not found
 */


/**
 * Check to make sure the credentials were supplied
 * @param {Object} obj - Object containing credentials to check
 * @param {checkCredentialsCallback} callback - Callback to run after finished checking credentials
 */
Adapter.prototype.checkCredentials = function (obj, callback) {
  username = this.getVal(obj, this.config.user.username);
  password = this.getVal(obj, this.config.user.password);

  if(!username || !password) {
    return callback(this.config.errmsg.un_and_pw_required, obj);
  } else {
    return callback(null, obj);
  }
};

/**
 * Handles response for ischeckCredentials method
 * @callback checkCredentialsCallback
 * @param {String} err - error message, if any
 * @param {Object} doc - Object that was passed in
 */


/**
 * Hashes a password using a path in a given object as the value
 * @param {Object} source_object - object to pull the password from
 * @param {Object} dest_object - object to save the password to
 * @param {String} path - path to the password field
 * @param {hashPasswordCallback} callback - return error and/or object with hashed password when finished
 */
Adapter.prototype.hashPassword = function (source_object,dest_object, path, callback) {
  var password = this.getVal(source_object, path);
  var self = this;
  bcrypt.genSalt(this.config.security.hash_salt_factor, function (err, salt) {
    if(err) {
      return callback(err, null);
    } else {
      bcrypt.hash(password, salt, function (err, hash) {
        if(err) {
         return callback(err, null);
        } else {
          source_object = self.buildQuery(dest_object, path, hash);
          return callback(err, dest_object);
        }
      });
    }
  });
};

/**
 * Handles response for hashPassword method
 * @callback hashPasswordCallback
 * @param {String} err - error message, if any
 * @param {Object} dest_object - Returns the object passed to the function with the hashed password in place of the plain-text password
 */



/**
 * Compare the supplied password with the stored hashed password
 * @param {Object} user - original user object
 * @pram {Object} login - login object containing the password to test
 * @param {comparePasswordCallback} callback - execute callback after the comparison
 */
Adapter.prototype.comparePassword = function (user, login, callback) {
  var self = this;
  var db_pass = this.getVal(user, this.config.user.password);
  var supplied_pass = this.getVal(login, this.config.user.password);
  if(this.config.security.hash_password){
      bcrypt.compare(supplied_pass, db_pass, function (err, match) {

    if(match) {
      return callback(null, user);
    } else {

      if(self.config.security.max_failed_login_attempts) {
        self.incrementFailedLogins(user, function (err) {
          return callback(err, user);
        });
      } else {
        return callback(self.config.errmsg.password_incorrect);
      }
    }
  });
  } else {

    if(db_pass === supplied_pass){
      return callback(null, user);
    } else {
      if(self.config.security.max_failed_login_attempts){
        this.incrementFailedLogins(user, function(err){
          return callback(err, user);
        });
      } else {
        return callback(self.config.errmsg.password_incorrect, user);
      }
    }
  }

};

/**
 * Handles response for comparePassword method
 * @callback comparePasswordCallback
 * @param {String} err - error message, if any
 * @param {Object} user - Returns the user object supplied initially
 */

/**
 * Checks to see if the user's failed attempts are expired and resets them if they are.
 * @param {Object} user - user to check
 * @param {failedAttemptsExpiredCallback} callback - execute a callback when the function is finished
 * @return {Callback}
 */
Adapter.prototype.failedAttemptsExpired = function (user, callback) {
  var now = moment();
  var last_failed_attempt = this.getVal(user, this.config.user.account_last_failed_attempt);
  var attempts_expire = moment(last_failed_attempt).add(this.config.security.reset_attempts_after_minutes, 'minutes');
  if(now.isAfter(attempts_expire)) {
    this.resetFailedLoginAttempts(user, function () {
      callback(null, true);
    });
  } else {
    return callback(null, false);
  }
};

/**
 * Handles response for failedAttemptsExpired method
 * @callback failedAttemptsExpiredCallback
 * @param {String} err - error message, if any
 * @param {Boolean} expired - Returns true if the attempts were expired, false if not
 */

/**
 * Save the user's new password once it has been hashed
 * @param {Object} user - user object to save, including the hashed password
 * @param {resetPasswordCallback} callback - execute a callback after the attempts are reset
 */
Adapter.prototype.resetPassword = function (user, callback) {
  var query = this.buildSimpleQuery(this.config.user.username, this.getVal(user, this.config.user.username));
  this.db.update(query, user, function (err, doc) {
    if(err) {
      throw err;
    }
    if(!doc){
      callback(new Error('Could not reset user password'), null);
    } else {
      callback(err, doc);
    }
  });
};

/**
 * Handles response for resetPassword method
 * @callback resetPasswordCallback
 * @param {String} err - error message, if any
 * @param {Object} doc - Returns the number of documents updated
 */


/**
 * Check to see if the account is locked.
 * First checks to see if there is a lock. If there is, checks to see if the lock has expired.
 * @param {Object} user - user object to check
 * @param {isAccountLockedCallback} callback - execute a callback after finished checking lock status
 */
Adapter.prototype.isAccountLocked = function (user, callback) {
  var isLocked = this.getVal(user, this.config.user.account_locked);
  var unlocked_at;
  if(isLocked) {
    unlocked_at = this.getVal(user, this.config.user.account_locked_until);
    var now = moment();
    var expires = moment(unlocked_at);
    if(now.isAfter(expires)) {
      this.unlockUserAccount(user, function () {
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

/**
 * Handles response for isAccountLocked method
 * @callback isAccountLockedCallback
 * @param {String} err - error message, if any
 * @param {Boolean} isLocked - True if the account is locked, false if not
 */

/**
 * Checks to see if the user's email address is verified
 * @param {Object} user - user account to check
 * @return {Boolean} 
 */
Adapter.prototype.isEmailVerified = function (user) {
  var isVerified = this.getVal(user, this.config.user.email_verified);
  return isVerified;
};

/**
 * Create email verification code using the username and current datetime.
 * Sets expiration to now + number of hours defined in authr config (config.security.email_verification_expiration_hours)
 * @param {Object} obj - Object to modify
 * @param {doEmailVerificationCallback} callback - Run a callback when finished
 */
Adapter.prototype.doEmailVerification = function (obj, callback) {
  var self = this;
  this.generateToken(20, function (err, token) {
    if(err){
      return callback(err, null);
    } else {
       obj = self.buildQuery(obj, self.config.user.email_verification_hash, token);
    obj = self.buildQuery(obj, self.config.user.email_verification_hash_expires, moment().add(self.config.security.email_verification_expiration_hours, 'hours').toDate());
    obj = self.buildQuery(obj, self.config.user.email_verified, false);
    return callback(null, obj);
    }
  });

};

/**
 * Handles response for doEmailVerification method
 * @callback doEmailVerificationCallback
 * @param {String} err - error message, if it exists
 * @param {Object} obj - object passed in, plus the verification token and expiration
 */


/**
 * Generate a signup or password reset token using node crypto
 * @param size - size
 * @param {generateTokenCallback} callback - execute a callback after the token is generated
 */
Adapter.prototype.generateToken = function(size, callback){
  crypto.randomBytes(size, function(err, buf) {
    if(err) throw err;
        var token = buf.toString('hex');
        callback(err, token);
      });
};

/**
 * Handles response for generateToken method
 * @callback generateTokenCallback
 * @param {String} err - error message, if it exists
 * @param {Object} obj - generated token
 */


/**
 * Persist the password reset token to the database.
 * @param {String} token - the token to save
 * @param {Callback} callback - the callback to run atfter the token is saved
 * @return {Callback}
 */
Adapter.prototype.savePWResetToken = function(user, token, callback){
  var self = this;
  user = this.buildQuery(user, this.config.user.password_reset_token, token);
  var hours_to_add = this.config.security.password_reset_token_expiration_hours;
  token_expiration = moment().add(hours_to_add, 'hours').toDate();
  user = this.buildQuery(user, this.config.user.password_reset_token_expiration, token_expiration);
  var query = this.buildSimpleQuery(this.config.user.username, this.getVal(user, this.config.user.username));
  this.db.update(query, user, function(err, doc){
    if(err) throw err;
    if(!doc){
      return callback('User could not be updated');
    } else {
      return callback(err, user);
    }
  });
};

/**
 * Handles response for savePWResetToken method
 * @callback savePWResetCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - saved user
 */

/**
 * Create account security defaults
 * @param {Object} obj - object to add to
 * @return {Object} obj - object containing accoutn security settings
 */
Adapter.prototype.buildAccountSecurity = function (obj) {
  obj = this.buildQuery(obj, this.config.user.account_locked, false);
  obj = this.buildQuery(obj, this.config.user.account_locked_until, null);
  obj = this.buildQuery(obj, this.config.user.account_failed_attempts, 0);
  obj = this.buildQuery(obj, this.config.user.account_last_failed_attempt, null);
  return obj;
};

/**
 * Saves the user saved in this.signup. Callback returns any errors and the user, if successfully inserted
 * @param {Object} user - user to save
 * @param {saveUserCallback} callback - Run a callback after the user has been inserted
 */
Adapter.prototype.saveUser = function (user, callback) {
  this.db.insert(user, function (err, doc) {
    return callback(err, doc);
  });
};

/**
 * Handles response for saveUser method
 * @callback saveUserCallback
 * @param {String} err - error message, if it exists
 * @param {Object} doc - user that was saved
 */

/**
 * Looks for user account using email verification token
 * @param {String} token - verification token to look for
 * @param {findVerificationTokenCallback} callback - execute callback when account is found
 */
Adapter.prototype.findVerificationToken = function (token, callback) {
  var self = this;

  var query = this.buildSimpleQuery(this.config.user.email_verification_hash, token);

  this.db.findOne(query, function (err, user) {
    if(err) {
      return callback(err);
    }
    if(!user) {
      return callback(self.config.errmsg.token_not_found, null);
    } else {
      return callback(null, user);
    }
  });
};

/**
 * Handles response for findVerificationToken method
 * @callback findVerificationTokenCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user associated with the token
 */

/**
 * Looks for user account using password reset token
 * @param {String} token - reset token to look for
 * @param {findResetTokenCallback} callback - execute callback when account is found
 * @return {Callback}
 */
Adapter.prototype.findResetToken = function (token, callback) {
  var self = this;

  var query = this.buildSimpleQuery(this.config.user.password_reset_token, token);

  this.db.findOne(query, function (err, user) {
    if(err) {
      throw err;
    }
    if(!user) {
      return callback(self.config.errmsg.token_not_found, null);
    } else {
      return callback(null, user);
    }
  });
};

/**
 * Handles response for findResetToken method
 * @callback findResetTokenCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user associated with reset token
 */

/**
 * Check to see if the signup token is expired
 * @return {Boolean}
 */
Adapter.prototype.emailVerificationExpired = function (user) {
  var now = moment();
  expr = this.getVal(user, this.config.user.email_verification_hash_expires);
  var expires = moment(expr);
  if(now.isAfter(expires)) {
    return true;
  } else {
    return false;
  }
};

/**
 * Check to see if the password reset token is expired
 * @param {Object} user - user to pull reset token from for expiration check
 * @return {Boolean}
 */
Adapter.prototype.resetTokenExpired = function (user) {
  var now = moment();
  expr = this.getVal(user, this.config.user.password_reset_token_expiration);
  var expires = moment(expr);
  if(now.isAfter(expires)) {
    return true;
  } else {
    return false;
  }
};


/**
 * Verify email address in the datastore
 * @param {Object} user = object containing user to verify
 * @param {Callback} callback - Execute a callback when done inserting
 * @return {verifyEmailAddressCallback} callback
 */
Adapter.prototype.verifyEmailAddress = function (user, callback) {
  user = this.buildQuery(user, this.config.user.email_verified, true);
  var self = this;
  var username = this.getVal(user, this.config.user.username);
  var find_query = this.buildSimpleQuery(this.config.user.username, username);
  this.db.update(find_query, user, function (err, user) {
    callback(err, user);
  });
};

/**
 * Handles response for verifyEmailAddress method
 * @callback verifyEmailAddressCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user that was deleted
 */

/**
 * Find an account by email address
 * @param {string} email - email address to look for
 * @param {getUserByEmailCallback} callback - callback to execute when finished
 * @return {Callback}
 */
Adapter.prototype.getUserByEmail = function(email, callback){
  var self = this;
  var query = this.buildSimpleQuery(this.config.user.email_address, email);

  this.db.findOne(query, function(err, doc){
    if(err) throw err;
    if(doc){
      return callback(null, doc);
    } else {
      return callback(self.config.errmsg.username_not_found, null);
    }
  });
};

/**
 * Handles response for getUserByEmail method
 * @callback getUserByEmailCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user found by query
 */

/**
 * Find an account by username
 * @param {string} username - username or email address to look for
 * @param {getUserByUsernameCallback} callback - callback to execute when finished
 */
Adapter.prototype.getUserByUsername = function(username, callback){
  var self = this;
  var query = this.buildSimpleQuery(this.config.user.username, username);
  this.db.findOne(query, function(err, doc){
    if(err) throw err;
    if(doc){
      self.user = doc;
      return callback(null, doc);
    } else {
      return callback(self.config.errmsg.username_not_found, null);
    }
  });
};

/**
 * Handles response for getUserByUsername method
 * @callback getUserByUsernameCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user returned by query
 */

/**
 * Delete a user account
 * @param {Object} user - object containing user to delete
 * @param {deleteAccountCallback} callback - callback to run when finished
 */
Adapter.prototype.deleteAccount = function(user, callback){
  var self = this;
  var username = this.getVal(user, this.config.user.username);
  var query = this.buildSimpleQuery(this.config.user.username, username);
  this.db.remove(query, {}, function(err, docs){
    if(err) throw Err;
    if(!docs){
      return callback(new Error('User could not be deleted'));
    } else {
      callback(null, user);
    }
  });
};

/**
 * Handles response for deleteAccount method
 * @callback deleteAccountCallback
 * @param {String} err - error message, if it exists
 * @param {Object} user - user that was deleted
 */


// INTERNAL METHODS
// ----------------

/**
 * Look up a key's value when given the path as a string mimicing dot-notation.
 * Used recreate the user object with the correct keys and proper nesting before inserting the document
 * This allows for customizing the user document structure as desired.
 * @function
 * @private
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
 * @private
 * @name buildQuery
 * @param {Object} query - Object to add a key/value to
 * @param {String} path - String representation of path. E.g., 'some.nested.path' or 'top_level_path'
 * @param {*} value - value to insert into the path param's location
 * @return {Object}
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
 * @private
 * @name buildSimpleQuery
 * @param {String} key - The key to give the query
 * @param {*} value - The value to give
 * @return {Object}
 */
Adapter.prototype.buildSimpleQuery = function (key, value) {
  return JSON.parse('{"' + key + '":"' + value + '"}');
};


/**
 * Called after a failed login attempt. Either increment the number of failed login attempts and report the error or lock the account and report that.
 * @function
 * @private
 * @name incrementFailedLogins
 * @param {Object} user - user to increment logins for
 * @param {Callback} callback - execute a callback after the function runs
 * @return {Callback}
 */
Adapter.prototype.incrementFailedLogins = function (user, callback) {
  var current_failed_logins = this.getVal(user, this.config.user.account_failed_attempts) + 1;
  var max_failed_attempts = this.config.security.max_failed_login_attempts;
  var query;
  var msg;
  var self = this;
  if(current_failed_logins >= max_failed_attempts) {
    this.lockUserAccount(user, function (user, err) {
      return callback(err, user);
    });
  } else {
    user = this.buildQuery(user, this.config.user.account_failed_attempts, current_failed_logins);
    msg = this.config.errmsg.password_incorrect.replace('##i##', max_failed_attempts - current_failed_logins);
    errmsg = {
      err: msg,
      remaining_attempts: max_failed_attempts - current_failed_logins
    };
    query = this.buildSimpleQuery(this.config.user.username, this.getVal(user, this.config.user.username));
    this.db.update(query, user, function (err, doc) {
      if(err) {
        throw err;
      }
      if(!doc) {
        return callback('Failed login attempts could not be incremented');
      }

      return callback(errmsg);
    });
  }
};

/**
 * Unlock a user's account (e.g., if the lock has expired)
 * @function
 * @private
 * @name unlockUserAccount
 * @param {Callback} user - user to unlock
 * @param {Callback} callback - execute a callback after the account is unlocked.
 */
Adapter.prototype.unlockUserAccount = function (user, callback) {
  this.user = this.buildQuery(user, this.config.user.account_locked, false);
  var query = this.buildSimpleQuery(this.config.user.username, this.getVal(user, this.config.user.username));
  this.db.update(query, user, function (err, docs) {
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
 * @private
 * @name lockUserAccount
 * @param {Object} user - user account to lock
 * @param {Callback} callback - execute a callback after the lock
 */
Adapter.prototype.lockUserAccount = function (user, callback) {
  var expires;
  var query;
  var errmsg = this.config.errmsg.account_locked.replace('##i##', this.config.security.lock_account_for_minutes);
  var self = this;
  expires = moment().add(this.config.security.lock_account_for_minutes, 'minutes');
  this.user = this.buildQuery(user, this.config.user.account_locked, true);
  this.user = this.buildQuery(user, this.config.user.account_locked_until, expires.toDate());
  query = this.buildSimpleQuery(this.config.user.username, this.getVal(user, this.config.user.username));
  this.db.update(query, this.user, function (err, doc) {
    if(err) {
      throw err;
    }

    if(!doc) {
      callback('Account could not be locked');
    }
    errobj = {
      err: errmsg,
      lock_until: expires.toDate()
    };
    callback(errobj);
  });
};

/**
 * Reset failed login attempts
 * @function
 * @private
 * @name resetFailedLoginAttempts
 * @param {Object} user - user to reset expired login attempts for
 * @param {Callback} - execute a callback after the attempts are reset
 */
Adapter.prototype.resetFailedLoginAttempts = function (user, callback) {
  user = this.buildQuery(user, this.config.user.account_failed_attempts, 0);
  var query = this.buildSimpleQuery(this.config.user.username, this.getVal(user, this.config.user.username));
  this.db.update(query, user, function (err, doc) {
    if(err) {
      throw err;
    }
    callback(doc);
  });
};

/**
 * Remove the collection. Mostly used for testing. Will probably find a use for it.
 * @function
 * @private
 * @name resetCollection
 * @param {Callback} callback - Execute callback when finished dropping the collection
 * @return {Callback}
 */
Adapter.prototype.resetCollection = function (callback) {
  this.db.remove({}, {
    multi: true
  }, function (err) {
    if(err) throw err;
    callback(err);
  });
};

module.exports = Adapter;