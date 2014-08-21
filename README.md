authr-nedb
=====
## Introduction
This is the default adapter used for [authr](https://www.npmjs.org/package/authr).

## Usage

This module is required by authr and will be used automatically if you do not specify any database configuration options.

**Note:** This is an in-memory database only. As soon as your node app stops, the data will be lost. Do not use it in production.

1. Install authr

`npm install authr`

2. Set up authr

```
var Authr = require('authr');
var authr = new Authr(); // use the default configuration

var signup = {
    username: 'some_user',
    password: 'super_secure'
}

authr.signUp(signup, function(user){
    console.log(user); // returns the user inserted into nedb.
});
```

## Todo
1. Refactor

