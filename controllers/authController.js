const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
require('dotenv').config({ path: './config.env' });

const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const Email = require('../utils/email');
const { runInNewContext } = require('vm');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = catchAsync(async (user, statusCode, res, req) => {
  const token = signToken(user._id);

  // Generate the random refresh token
  const refreshToken = crypto.randomBytes(32).toString('hex');

  const hashedRefreshToken = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  const refreshExpiration = new Date().setDate(new Date().getDate() + 7); // 7 days

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV == 'production' ? true : false,
    maxAge: 604800000, // 7 days
  });

  res.cookie('accessToken', token, {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV == 'production' ? true : false,
    maxAge: 1800000, // 30 minutes
  });

  await User.findByIdAndUpdate(user._id, {
    $push: {
      refreshTokens: {
        token: hashedRefreshToken,
        expiration: refreshExpiration,
      },
    },
  });

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // Get token and check if it exists
  let token;

  if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }

  if (!token) {
    return next(
      new AppError('You are not logged in. Please log in to get access', 401)
    );
  }

  try {
    // Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    const currentUser = await User.findById(decoded.id);

    if (!currentUser) {
      return next(
        new AppError('The user belonging to this token no longer exists.', 401)
      );
    }

    // Grant access to protected route
    req.user = currentUser;
  } catch (err) {
    console.log(err);
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // Roles in an array
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

exports.sendAuthLink = catchAsync(async (req, res, next) => {
  // Get user based on the POSTed email
  let user = await User.findOne({ email: req.body.email });

  if (!user) {
    user = await User.create({
      email: req.body.email,
    });
  }

  // Generate the random auth token
  const authToken = user.createAuthToken();
  await user.save({ validateBeforeSave: false });

  const authLink = `${process.env.HOST}/verify#loginToken=${authToken}`;

  try {
    await new Email(user, authLink).sendMagicLink();

    res.status(200).json({
      status: 'success',
      message: 'Check your email to complete login.',
    });
  } catch (err) {
    user.authLoginToken = undefined;
    user.authLoginExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        'There was an error sending the email. Try again later.',
        500
      )
    );
  }
});

exports.verifyAuthLink = catchAsync(async (req, res, next) => {
  // Get user based on token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    authLoginToken: hashedToken,
    authLoginExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError('Token is invalid or expired.', 400));
  }

  user.authLoginToken = undefined;
  user.authLoginExpires = undefined;
  await user.save();

  // Log the user in and send JWT
  createSendToken(user, 200, res, req);
});

exports.logout = catchAsync(async (req, res, next) => {
  // Remove refreshTokens from database
  req.user.refreshTokens = [];

  // Set cookies to expired
  res.cookie('refreshToken', 'loggedout', {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV == 'production' ? true : false,
    maxAge: 0,
  });

  res.cookie('accessToken', 'loggedout', {
    httpOnly: true,
    sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
    secure: process.env.NODE_ENV == 'production' ? true : false,
    maxAge: 0,
  });

  await req.user.save();

  res.status(200).json({
    stutus: 'success',
    data: {},
  });
});

exports.isLoggedIn = catchAsync(async (req, res, next) => {
  let token;
  let refresh;

  if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }

  if (req.cookies && req.cookies.refreshToken) {
    refresh = req.cookies.refreshToken;
  }

  if (!token && !refresh) {
    return next(new AppError('You are not logged in.', 401));
  }

  // Attempt to get a new auth token with refresh token
  if (!token && refresh) {
    try {
      // Get user based on hashed refresh token
      const hashedRefreshToken = crypto
        .createHash('sha256')
        .update(refresh)
        .digest('hex');

      // Check if user exists with refresh token
      const refreshUser = await User.findOne({
        'refreshTokens.token': hashedRefreshToken,
        'refreshTokens.expiration': { $gt: Date.now() },
      });

      if (!refreshUser) {
        return next(new AppError('You are not logged in.', 401));
      }

      // Create a new token
      const refreshAuthToken = signToken(refreshUser._id);

      // Send new access token in cookie
      res.cookie('accessToken', refreshAuthToken, {
        httpOnly: true,
        sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'Lax',
        secure: process.env.NODE_ENV == 'production' ? true : false,
        maxAge: 1800000, // 30 minutes
      });

      // There is a logged in user
      res.status(200).json({ status: 'success', data: refreshUser });
    } catch (err) {
      res.status(401).json({ status: 'error', data: null });
    }
  }

  if (token) {
    try {
      // Verify token
      const decoded = await promisify(jwt.verify)(
        token,
        process.env.JWT_SECRET
      );

      // Check if user still exists
      const currentUser = await User.findById(decoded.id);

      if (!currentUser) {
        return res.status(401).json({ status: 'error', data: null });
      }

      res.status(200).json({ status: 'success', data: currentUser });
    } catch (err) {
      res.status(401).json({ status: 'error', data: null });
    }
  }
});
