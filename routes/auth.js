const authController = require('../controllers/authControllers');
const middlewareController = require('../controllers/middleWareController');

const router = require('express').Router();

// REGISTER
router.post('/register', authController.registerUser);

// LOGIN
router.post('/login', authController.loginUser);

// REFRESHTOKEN
router.post('/refresh', authController.requestRefreshToken);

// LOGOUT
router.post(
    '/logout',
    middlewareController.verifyToken,
    authController.userLogout,
);

module.exports = router;
