const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Set up the Express app
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mydb', { useNewUrlParser: true, useUnifiedTopology: true });

// Define User schema and model
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});

const User = mongoose.model('User', userSchema);

// Register endpoint
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered');
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid email or password');
    }
    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token });
});

// Middleware for authenticating JWT tokens
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
    res.send('This is a protected route');
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
