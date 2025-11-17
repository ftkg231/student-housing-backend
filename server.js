const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Kết nối MySQL - Sử dụng biến môi trường
const db = mysql.createConnection({
    host: process.env.MYSQL_HOST || 'localhost',
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_DATABASE || 'student_housing',
    port: process.env.MYSQL_PORT || 3306
});

// Kết nối database
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// API Đăng ký
app.post('/api/register', async (req, res) => {
    const { name, email, password, phone } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const query = 'INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)';
        db.execute(query, [name, email, hashedPassword, phone], (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Email already exists' });
            }
            res.json({ message: 'User registered successfully' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// API Đăng nhập
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    const query = 'SELECT * FROM users WHERE email = ?';
    db.execute(query, [email], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email }, 
            process.env.JWT_SECRET || 'fallback_secret', 
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            user: { 
                id: user.id, 
                name: user.name, 
                email: user.email 
            } 
        });
    });
});

// API Lấy danh sách nhà trọ
app.get('/api/properties', (req, res) => {
    const query = `SELECT p.*, u.name as owner_name 
                  FROM properties p 
                  JOIN users u ON p.owner_id = u.id`;
    
    db.execute(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(results);
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ message: 'Student Housing Backend API' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
