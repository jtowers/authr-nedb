var should = require('chai').should();
var Adapter = require('../index.js');

describe('adapter', function () {
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
    adapter.connect(function(err){
      should.not.exist(err);
      done();
    });
  });

  it('should have the right database object', function(done){
    adapter.connect(function(err){
      should.exist(adapter.db);
      done();
    });
  });

  it('should be able to disconnect from database', function(done){
    adapter.connect(function(error){
      adapter.disconnect(function(err){
        should.not.exist(err);
        done();
      });
    });
  });



});