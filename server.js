const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// Настройка CORS для продакшена
const corsOptions = {
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://ваш-домен.com', 'https://www.ваш-домен.com']
        : '*',
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Безопасность в продакшене
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        // Принудительно используем HTTPS
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect('https://' + req.headers.host + req.url);
        }
        next();
    });
}

// Переменные окружения
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// База данных
const dbPath = process.env.NODE_ENV === 'production' 
    ? '/data/database.db'  // Для Render.com
    : './database.db';

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
    } else {
        console.log('Подключено к базе данных SQLite:', dbPath);
        initDatabase();
    }
});

function initDatabase() {
    db.serialize(() => {
        // Таблица пользователей
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0
        )`);

        // Таблица балансов
        db.run(`CREATE TABLE IF NOT EXISTS balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            real_balance REAL DEFAULT 0,
            bonus_balance REAL DEFAULT 0,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        // Таблица транзакций
        db.run(`CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            balance_type TEXT NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )`);

        // Создаем администратора
        const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
        db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
            if (!row) {
                db.run(
                    'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                    ['admin', 'admin@example.com', adminHash, 1]
                );
                console.log('✅ Администратор создан. Логин: admin');
            }
        });
    });
}

// ========== API ENDPOINTS ==========

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: err.message });
                }
                
                db.run(
                    'INSERT INTO balances (user_id, bonus_balance) VALUES (?, ?)',
                    [this.lastID, 100]
                );
                
                const token = jwt.sign(
                    { userId: this.lastID, username },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );
                
                res.json({ 
                    success: true, 
                    token,
                    userId: this.lastID 
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Авторизация
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Неверные данные' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверные данные' });
        }
        
        const token = jwt.sign(
            { 
                userId: user.id, 
                username: user.username,
                is_admin: user.is_admin 
            }, 
            JWT_SECRET, 
            { expiresIn: '7d' }
        );
        
        res.json({ 
            success: true, 
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin
            }
        });
    });
});

// Получение баланса
app.get('/api/user/balance', authenticateToken, (req, res) => {
    db.get(
        'SELECT real_balance, bonus_balance FROM balances WHERE user_id = ?',
        [req.user.userId],
        (err, balance) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(balance || { real_balance: 0, bonus_balance: 0 });
        }
    );
});

// Обновление баланса
app.post('/api/user/balance/update', authenticateToken, (req, res) => {
    const { real_balance, bonus_balance, description } = req.body;
    
    db.run(
        `UPDATE balances 
         SET real_balance = COALESCE(?, real_balance),
             bonus_balance = COALESCE(?, bonus_balance),
             last_updated = CURRENT_TIMESTAMP
         WHERE user_id = ?`,
        [real_balance, bonus_balance, req.user.userId],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            if (description) {
                const amount = real_balance !== undefined ? real_balance : bonus_balance;
                const type = real_balance !== undefined ? 'real' : 'bonus';
                
                db.run(
                    'INSERT INTO transactions (user_id, type, amount, balance_type, description) VALUES (?, ?, ?, ?, ?)',
                    [req.user.userId, 'update', amount, type, description]
                );
            }
            
            res.json({ success: true });
        }
    );
});

// Проверка пользователя (публичный)
app.get('/api/user/check/:username', (req, res) => {
    db.get(
        'SELECT id, username, email, created_at FROM users WHERE username = ?',
        [req.params.username],
        (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ exists: !!user, user: user || null });
        }
    );
});

// Получение транзакций
app.get('/api/user/transactions', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
        [req.user.userId],
        (err, transactions) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(transactions);
        }
    );
});

// Проверка JWT токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Токен отсутствует' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Неверный токен' });
        req.user = user;
        next();
    });
}

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Все остальные маршруты ведут на index.html (для SPA)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
    console.log(`🌍 Режим: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 База данных: ${dbPath}`);
});