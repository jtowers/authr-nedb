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
function Adapter(config){
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
Adapter.prototype.connect = function(callback){
  return callback();
};

/**
 * Dummy disconnect function. Just returns the callback, since in-memory nedb doesn't require loading a database
 * @function
 * @name disconnect
 * @param {Callback} callback - execute callback after connection
 * @return {Callback}
 */
Adapter.prototype.disconnect = function(callback){
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
Adapter.prototype.signupConfig = function(signup){
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
Adapter.prototype.getVal = function(obj, str){
    return str.split(".").reduce(function(o, x) { return o[x]; }, obj);
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
Adapter.prototype.buildQuery = function(query, path, value){
  var obj = query;
    var schema = obj;  // a moving reference to internal objects within obj
    var pList = path.split('.');
    var len = pList.length;
    for(var i = 0; i < len-1; i++) {
        var elem = pList[i];
        if( !schema[elem] ) schema[elem] = {};
        schema = schema[elem];
    }

    schema[pList[len-1]] = value;
return obj;
};

/**
 * Check to see if the username is taken
 * @function
 * @name isUsernameTaken
 * @param {Function} cb - Run callback when finished connecting
 * @return {Function}
 */
Adapter.prototype.isUsernameTaken = function(cb){
  var username = this.getVal(this.signup, this.config.user.username);
  var query = JSON.parse('{"' + this.config.user.username + '":"' + username + '"}');
  var self = this;
  this.db.findOne(query, function(err, doc){
    if(err){
      throw err;
    }

    if(doc){
      return cb(true);
    } else {
      return cb(false);
    }

    });
  };

/**
 * Hashes the password using bcrypt and the settings specified in the authr config
 * @function
 * @name hash_password
 * @param {Callback} callback - run a callback when hashing is complete
 * @return {Callback}
 */
Adapter.prototype.hash_password = function(callback){
  var password = this.getVal(this.signup, this.config.user.password);
  var self = this;
  bcrypt.genSalt(this.config.security.hash_salt_factor, function(err, salt){
    if(err){
      callback(err);
    } else {
      bcrypt.hash(password, salt, function(err, hash){
        if(err){
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
 * Create email verification code using the username and current datetime.
 * Sets expiration to now + number of hours defined in authr config (config.security.email_verification_expiration_hours)
 * @function
 * @name doEmailVerification
 * @param {Callback} callback - Run a callback when finished
 * @return {Callback}
 */
Adapter.prototype.doEmailVerification = function(callback){
  var now = moment().format("dddd, MMMM Do YYYY, h:mm:ss a");
  var username = this.getVal(this.signup, this.config.user.username);
  var hash = crypto.createHash('md5').update(username + now).digest('hex');
  this.signup = this.buildQuery(this.signup, this.config.user.email_verification_hash, hash);
  this.signup = this.buildQuery(this.signup, this.config.user.email_verification_hash_expires, moment().add(this.config.security.email_verification_expiration_hours, 'h').toDate());
  this.signup = this.buildQuery(this.signup, this.config.user.email_verified, false);
  return callback();
};

/**
 * Create account security defaults
 * @function
 * @name doEmailVerification
 */
Adapter.prototype.buildAccountSecurity = function(){
  this.signup = this.buildQuery(this.signup, this.config.user.account_locked, false);
  this.signup = this.buildQuery(this.signup, this.config.user.account_locked_until, null);
  this.signup = this.buildQuery(this.signup, this.config.user.account_failed_attempts, 0);
  this.signup = this.buildQuery(this.signup, this.config.user.account_last_failed_attempt, null);
};

/**
 * Saves the user saved in this.signup. Callback returns any errors and the user, if successfully inserted
 * @function
 * @name saveUser
 * @param {Callback} callback - Run a callback after the user has been inserted
 * @return {Callback}
 */
Adapter.prototype.saveUser = function(callback){
  this.db.insert(this.signup, function(err, doc){
      return callback(err,doc);
  });
};


/**
 * Remove the collection. Mostly used for testing. Will probably find a use for it.
 * @function
 * @name resetCollection
 * @param {Callback} callback - Execute callback when finished dropping the collection
 * @return {Callback}
 */ 
Adapter.prototype.resetCollection = function(callback){
  this.db.remove({}, function(err){
      callback(err);
  });
};

module.exports = Adapter;
