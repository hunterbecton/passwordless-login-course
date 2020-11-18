const dotenv = require('dotenv');
const mongoose = require('mongoose');

const app = require('./app');

dotenv.config({ path: './config.env' });

const DB =
  process.env.NODE_ENV == 'production'
    ? process.env.DATABASE_PROD
    : process.env.DATABASE_DEV;

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('DB Connection Successful');
  });

const port = process.env.PORT || 4010;

const server = app.listen(port, () => {
  console.log(`App running on port ${port} ...`);
});
