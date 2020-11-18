const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');

const refreshToken = new mongoose.Schema({
  token: {
    type: String,
    trim: true,
  },
  expiration: {
    type: Date,
  },
  issued: {
    type: Date,
    default: Date.now(),
  },
  select: false,
});

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      required: [true, 'Email cannot be empty'],
      trim: true,
      lowercase: true,
      validate: [validator.isEmail],
    },
    authLoginToken: {
      type: String,
      select: false,
    },
    authLoginExpires: {
      type: Date,
      select: false,
    },
    refreshTokens: [refreshToken],
    active: {
      type: Boolean,
      default: true,
      select: false,
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
  },
  { timestamps: true }
);

userSchema.methods.createAuthToken = function () {
  const authToken = crypto.randomBytes(32).toString('hex');

  this.authLoginToken = crypto
    .createHash('sha256')
    .update(authToken)
    .digest('hex');

  this.authLoginExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  return authToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
