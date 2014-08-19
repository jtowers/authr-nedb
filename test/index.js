var should = require('chai').should();
var Adapter = require('../index');
var moment = require('moment');
describe('default adapter', function () {
  describe('constructor', function () {
    var adapter;
    var signup_config;
    var authr_config;
    beforeEach(function (done) {
      authr_config = {
        user: {
          username: 'account.username',
          password: 'account.password',
          account_locked: 'account.locked.account_locked',
          account_locked_until: 'account.locked.account_locked_until',
          account_failed_attempts: 'account.locked.account_failed_attempts',
          account_last_failed_attempt: 'account.locked.account_last_failed_attempt',
          email_address: 'account_username',
          email_verified: 'email.email_verified',
          email_verification_hash: 'email.email_verification_hash',
          email_verification_hash_expires: 'email.email_verification_expires'
        },
        db: {
          type: 'nedb',
        },
        security: {
          hash_password: true,
          hash_salt_factor: 1, // salt work factor reduced for testing
          max_failed_login_attempts: 10,
          reset_attempts_after_minutes: 5,
          lock_account_for_minutes: 30,
          email_verification: true,
          email_verification_expiration_hours: 12
        },
        errmsg: {
          username_taken: 'This username is taken Please choose another.',
          token_not_found: 'This signup token does not exist. Please try again.',
          token_expired: 'This token has expired. A new one has been generated.',
          un_and_pw_required: 'A username and password are required to log in.',
          username_not_found: 'Username not found. Please try again or sign up.',
          password_incorrect: 'Password incorrect. Your account will be locked after ##i## more failed attempts.',
          account_locked: 'Too many failed attempts. This account will be locked for ##i## minutes.'
        }

      };

      adapter = new Adapter(authr_config);
      done();

    });

    it('should have the right db config', function (done) {
      adapter.config.db.type.should.equal('nedb');
      done();
    });

    it('should be able to connect to database', function (done) {
      adapter.connect(function (err) {
        should.not.exist(err);
        done();
      });
    });

    it('should have the right database object', function (done) {
      adapter.connect(function (err) {
        should.exist(adapter.db);
        done();
      });
    });

    it('should be able to disconnect from database', function (done) {
      adapter.connect(function (error) {
        adapter.disconnect(function (err) {
          should.not.exist(err);
          done();
        });
      });
    });
  });

  describe('signup', function () {
    var adapter;
    var signup_config;
    var authr_config;
    beforeEach(function (done) {
      authr_config = {
        user: {
          username: 'account.username',
          password: 'account.password',
          account_locked: 'account.locked.account_locked',
          account_locked_until: 'account.locked.account_locked_until',
          account_failed_attempts: 'account.locked.account_failed_attempts',
          account_last_failed_attempt: 'account.locked.account_last_failed_attempt',
          email_address: 'account.username',
          email_verified: 'email.email_verified',
          email_verification_hash: 'email.email_verification_hash',
          email_verification_hash_expires: 'email.email_verification_expires'
        },
        db: {
          type: 'nedb',
        },
        security: {
          hash_password: true,
          hash_salt_factor: 1, // salt work factor reduced for testing
          max_failed_login_attempts: 10,
          reset_attempts_after_minutes: 5,
          lock_account_for_minutes: 30,
          email_verification: true,
          email_verification_expiration_hours: 12
        },
        errmsg: {
          username_taken: 'This username is taken Please choose another.',
          token_not_found: 'This signup token does not exist. Please try again.',
          token_expired: 'This token has expired. A new one has been generated.',
          un_and_pw_required: 'A username and password are required to log in.',
          username_not_found: 'Username not found. Please try again or sign up.',
          password_incorrect: 'Password incorrect. Your account will be locked after ##i## more failed attempts.',
          account_locked: 'Too many failed attempts. This account will be locked for ##i## minutes.'
        }

      };

      signup_config = {
        account: {
          username: 'test@test.com',
          password: 'test'
        }
      };
      adapter = new Adapter(authr_config);
      adapter.signupConfig(signup_config);
      done();

    });

    describe('config', function () {
      it('should have the right signup config', function (done) {
        adapter.signup.should.equal(signup_config);
        done();
      });

    });

    describe('utilities', function () {

      it('should return null when username and password are supplied', function (done) {
        should.not.exist(adapter.checkCredentials());
        done();
      });

      it('should return null when username is missing', function (done) {
        adapter.signup.account.username = null;
        should.exist(adapter.checkCredentials());
        done();
      });

      it('should return null when password is missing', function (done) {
        adapter.signup.account.password = null;
        should.exist(adapter.checkCredentials());
        done();
      });

      it('should be able to get the value of an object using a string indicating its path', function (done) {
        var username = adapter.getVal(signup_config, 'account.username');
        username.should.equal(signup_config.account.username);
        done();
      });

      it('should be able to dynamically build mongodb objects for queries using the user key in the authr config', function (done) {
        test_query = {};
        test_query = adapter.buildQuery(test_query, 'account.username', 'test');
        test_query = adapter.buildQuery(test_query, 'account.password', 'test');
        test_query = adapter.buildQuery(test_query, 'email.email_verified', true);
        test_query.account.username.should.equal('test');
        test_query.account.password.should.equal('test');
        test_query.email.email_verified.should.equal(true);
        done();
      });
      it('should be able to hash a password', function (done) {
        adapter.hash_password(function (err, hash) {
          should.not.exist(err);
          hash.should.equal(adapter.signup.account.password);
          done();
        });
      });

      it('should be able to generate a verification hash', function (done) {
        adapter.doEmailVerification(adapter.signup, function (err) {
          should.not.exist(err);
          done();
        });
      });

      it('should be able to save users', function (done) {
        adapter.connect(function (err) {
          if(err) {
            throw err;
          }
          adapter.saveUser(function (err, user) {
            should.exist(user);
            adapter.disconnect(function () {
              done();
            });
          });
        });
      });

    });
    describe('db operations', function () {
      var saved_user;
      beforeEach(function (done) {
        user = {
          account: {
            username: 'test@test.com',
            password: 'test'
          }
        };
        adapter.connect(function (err) {
          if(err) {
            throw err;
          } else {
            adapter.doEmailVerification(adapter.signup, function (err) {
              if(err) {
                throw err;
              }
              adapter.buildAccountSecurity(adapter.signup);
              adapter.hash_password(function () {
                adapter.saveUser(function (err, user) {
                  saved_user = user;
                  done();
                });
              });
            });

          }
        });
      });

      afterEach(function (done) {
        adapter.resetCollection(function (err) {
          done();
        });
      });
      it('should be able to find duplicate users', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          isTaken.should.equal(true);
          done();
        });
      });

      it('should return null when username is not taken', function (done) {
        adapter.isUsernameTaken('not_in_use', function (isTaken) {
          isTaken.should.equal(false);
          done();
        });
      });

      it('should be able to check see if an email is verified', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.isEmailVerified().should.equal(false);
          done();
        });

      });
      it('should be able to retreive a verification hash', function (done) {
        adapter.findVerificationToken(saved_user.email.email_verification_hash, function (err, user) {
          should.not.exist(err);
          saved_user.email.email_verification_hash.should.equal(user.email.email_verification_hash);
          done();
        });
      });

      it('should be able to check the expiration date on an a verification hash', function (done) {
        adapter.findVerificationToken(saved_user.email.email_verification_hash, function (err, user) {
          isExpired = adapter.verificationExpired(adapter.user);

          isExpired.should.equal(false);
          done();
        });
      });

      it('should be able to mark email_verified as true', function (done) {
        adapter.findVerificationToken(saved_user.email.email_verification_hash, function (err, user) {
          adapter.verifyEmailAddress(function (err, user) {
            should.exist(user);
            user.email.email_verified.should.equal(true);
            done();
          });
        });

      });

      it('should return an error if the token is not found', function (done) {
        adapter.findVerificationToken('notatoken', function (err, user) {
          should.exist(err);
          
          err.should.equal(adapter.config.errmsg.token_not_found);
          done();
        });
      });
      it('should return false if the account is not locked', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.isAccountLocked(function (err, locked) {
            should.not.exist(err);
            locked.should.equal(false);
            done();
          });
        });
      });

      it('should return true if the account is locked', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.user.account.locked.account_locked = true;
          adapter.isAccountLocked(function (err, locked) {
            should.exist(err);
            err.err.should.equal(adapter.config.errmsg.account_locked);
            done();
          });
        });
      });

      it('should return true if the account is locked but the lock is expired', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.user.account.locked.account_locked = true;
          adapter.user.account.locked.account_locked_until = moment().add(-12, 'hours').toDate();
          adapter.isAccountLocked(function (err, locked) {
            should.not.exist(err);
            locked.should.equal(false);
            done();
          });
        });
      });

      it('should be able to lock an account', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.lockUserAccount(function (err) {
            should.exist(err);
            err.err.should.equal(adapter.config.errmsg.account_locked.replace('##i##', adapter.config.security.lock_account_for_minutes));
            done();
          });
        });
      });

      it('should be able to unlock an account', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.lockUserAccount(function (err) {
            adapter.unlockUserAccount(function () {
              adapter.user.account.locked.account_locked.should.equal(false);
              done();
            });

          });
        });
      });

      it('should expire failed login attempts', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.user = adapter.buildQuery(adapter.user, adapter.config.user.account_failed_attempts, 4);
          adapter.user = adapter.buildQuery(adapter.user, adapter.config.user.account_last_failed_attempt, moment().add(-1, 'hour').toDate());
          adapter.failedAttemptsExpired(function (err, reset) {
            adapter.user.account.locked.account_failed_attempts.should.equal(0);
            done();
          });
        });
      });

      it('should not expire attempts that aren\'t expired', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.user = adapter.buildQuery(adapter.user, adapter.config.user.account_failed_attempts, 4);
          adapter.user = adapter.buildQuery(adapter.user, adapter.config.user.account_last_failed_attempt, moment().toDate());
          adapter.failedAttemptsExpired(function (err, reset) {
            adapter.user.account.locked.account_failed_attempts.should.equal(4);
            done();
          });
        });
      });

      it('should increment the number of failed attempts after a failed attempt', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.incrementFailedLogins(function () {
            adapter.user.account.locked.account_failed_attempts.should.equal(1);
            done();
          });
        });
      });

      it('should lock an account after the specified number of failed login attempts', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function (isTaken) {
          adapter.user = adapter.buildQuery(adapter.user, adapter.config.user.account_failed_attempts, adapter.config.security.max_failed_login_attempts);
          adapter.incrementFailedLogins(function () {
            adapter.user.account.locked.account_locked.should.equal(true);
            done();
          });
        });
      });

      it('should increment the number of failed attempts when a bad password is supplied', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function () {
          adapter.comparePassword('not_really_it', function (err, doc) {
            should.exist(err);
            err.remaining_attempts.should.equal(9);
            done();
          });
        });
      });

      it('should return an error when password incorrect and account locking is disabled', function (done) {
        adapter.config.security.max_failed_login_attempts = 0;
        adapter.isUsernameTaken(saved_user.account.username, function () {
          adapter.comparePassword('not_really_it', function (err, doc) {
            should.exist(err);
            err.should.equal(adapter.config.errmsg.password_incorrect);
            done();
          });
        });
      });

      it('should return null when the password is correct', function (done) {
        adapter.isUsernameTaken(saved_user.account.username, function () {
          adapter.comparePassword('test', function (err, doc) {
            should.not.exist(err);
            done();
          });
        });
      });
    });
  });
});