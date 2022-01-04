const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true, //if not unique -> error
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

userSchema.pre('save', function (next) {
  //because we use this
  const user = this;
  if (!user.isModified('password')) {
    //if user did not modify his password
    return next();
  }

  bcrypt.genSalt(10, (err, salt) => {
    //10 - how complex the salt is
    if (err) {
      return next(err);
    }

    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function comparePassword(
  candidatePassword
) {
  const user = this;
  return new Promise((resolve, reject) => {
    //use promise because we want to use async
    bcrypt.compare(candidatePassword, user.password, (err, isMatch) => {
      if (err) {
        return reject(err);
      }

      if (!isMatch) {
        return reject(false);
      }

      return resolve(true);
    });
  });
};

mongoose.model('User', userSchema); //mongoose expects this line executed 1 time
