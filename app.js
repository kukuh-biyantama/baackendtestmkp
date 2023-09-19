const express = require('express');
const authRoutes = require('./auth');

const app = express();
const port = 3000;

app.use('/auth', authRoutes);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
