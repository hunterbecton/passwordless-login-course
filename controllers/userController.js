const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const APIFeatures = require('../utils/apiFeatures');
const filterObj = require('../utils/filterObj');

exports.updateMe = catchAsync(async (req, res, next) => {
  // Filter fields that are allowed
  const filteredBody = filterObj(req.body, 'email');

  // Update user
  const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
    new: true,
    runValidators: true,
  });

  if (!updatedUser) {
    return next(new AppError('No user found with that ID.', 404));
  }

  res.status(201).json({
    status: 'success',
    data: {
      updatedUser,
    },
  });
});

exports.getMe = catchAsync(async (req, res, next) => {
  // Execute query
  const me = await User.findById(req.user._id);

  res.status(200).json({
    status: 'success',
    data: {
      me,
    },
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user._id, {
    active: false,
  });

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

exports.updateUser = catchAsync(async (req, res, next) => {
  // Update user document
  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!updatedUser) {
    return next(new AppError('No user found with that ID.', 404));
  }

  res.status(201).json({
    status: 'success',
    data: {
      updatedUser,
    },
  });
});

exports.getAllUsers = catchAsync(async (req, res, next) => {
  // Execute query
  const features = new APIFeatures(User.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();

  const users = await features.query;

  res.status(201).json({
    status: 'success',
    data: {
      users,
    },
  });
});

exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID.', 404));
  }

  res.status(201).json({
    status: 'success',
    data: {
      user,
    },
  });
});

exports.deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID.', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});
