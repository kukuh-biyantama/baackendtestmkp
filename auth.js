const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const pool = require('./db');

const router = express.Router();
router.use(bodyParser.json());

const secretKey = 'mkptest'; 

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers.authorization;
  
    if (!token) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
  
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        res.status(401).json({ error: 'Token is not valid' });
        return;
      }
  
      req.user = decoded;
      next();
    });
}

router.post('/login', (req, res) => {
  const { email, password } = req.body;

  pool.query(
    'SELECT * FROM users WHERE email = $1',
    [email],
    async (error, results) => {
      if (error) {
        console.error('Database error:', error);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }

      if (results.rows.length === 0) {
        res.status(401).json({ error: 'Authentication failed' });
        return;
      }

      const user = results.rows[0];
      try {
        await bcrypt.compare(password, user.password);

        // Generate JWT token
        const token = jwt.sign({ email }, secretKey, { expiresIn: '3h' });
        res.json({ message: 'Authentication successful', token });
      } catch (bcryptError) {
        console.error('Password comparison error:', bcryptError);
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  );
});

router.post('/create-terminal', verifyToken, (req, res) => {
    const { terminalName } = req.body;
  
    if (!terminalName) {
      return res.status(400).json({ error: 'Terminal name is required' });
    }
    const newTerminal = {
      name: terminalName,
      createdBy: req.user.email, 
    };
    res.json({ message: 'Terminal created successfully', terminal: newTerminal });
 });


module.exports = router;
