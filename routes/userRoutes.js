const express = require('express');
const { route } = require('../app');

const authController = require('./../controllers/authController');
const userController = require('./../controllers/userController');

const router = express.Router();

router.post('/authLogin', authController.sendAuthLink);

router.post('/authVerify/:token', authController.verifyAuthLink);

router.get('/isLoggedIn', authController.isLoggedIn);

// Protected routes
router.use(authController.protect);

router.post('/logout', authController.logout);

router.get('/me', userController.getMe);

router.patch('/updateMe', userController.updateMe);

router.delete('/deleteMe', userController.deleteMe);

router.use(authController.restrictTo('admin'));

router.get('/', userController.getAllUsers);

router
  .route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

module.exports = router;
