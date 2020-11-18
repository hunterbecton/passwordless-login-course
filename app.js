const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const compression = require('compression');

const userRouter = require('./routes/userRoutes');
const AppError = require('./utils/appError');

const app = express();

// CORS options
const corsOptions = {
  origin: `${process.env.HOST}`,
  credentials: true,
};

// Use CORS
app.use(cors(corsOptions));

// Security HTTP headers
app.use(helmet());

// Limit requests
const limiter = rateLimit({
  max: 500,
  windowMs: 15 * 60 * 1000, // 15 minutes
  message: 'Too many requests from this IP. Please retry in 15 minutes.',
});

// Use limiter
app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization against noSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Compress text sent to client
app.use(compression());

// Routes
app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on the server.`, 404));
});

module.exports = app;
