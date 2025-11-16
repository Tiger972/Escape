const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

// ════════════════════════════════════════════════════════════════════════
// VULN-004: CRYPTOGRAPHIC FAILURES - Password Hashing
// Location: database.js (Lines 14-28)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: MD5 is cryptographically broken and can be cracked in seconds
// using rainbow tables. No salt is used, making all identical passwords
// have the same hash. This allows attackers to crack all passwords if the
// database is compromised.
//
// const crypto = require('crypto');
//
// function hashPassword(password) {
//   // MD5 - Fast and broken! Can be cracked instantly with rainbow tables
//   return crypto.createHash('md5').update(password).digest('hex');
// }

// SECURE CODE (AFTER REMEDIATION):
// Solution: Use bcrypt with salt rounds of 12. Bcrypt is designed to be slow
// and computationally expensive, making brute force attacks impractical.
// Each password gets a unique salt, preventing rainbow table attacks.

const SALT_ROUNDS = 12;

async function hashPassword(password) {
  try {
    // Bcrypt automatically generates salt and creates secure hash
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    return hash;
  } catch (err) {
    console.error('Password hashing error:', err);
    throw new Error('Failed to hash password');
  }
}

async function verifyPassword(password, hash) {
  try {
    // Securely compare password with stored hash
    const isValid = await bcrypt.compare(password, hash);
    return isValid;
  } catch (err) {
    console.error('Password verification error:', err);
    return false;
  }
}

// ════════════════════════════════════════════════════════════════════════
// Database Initialization
// ════════════════════════════════════════════════════════════════════════

async function initDatabase() {
  db.serialize(async () => {
    // Table users
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        balance REAL DEFAULT 1000.0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table orders
    db.run(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_name TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Table sessions
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Check if users already exist
    db.get('SELECT COUNT(*) as count FROM users', [], async (err, row) => {
      if (err) {
        console.error('Error checking users:', err);
        return;
      }

      if (row.count === 0) {
        // Create test users with bcrypt hashes
        const users = [
          {
            email: 'alice@example.com',
            password: await hashPassword('alice123'),
            name: 'Alice Smith',
            role: 'user',
            balance: 5000.0
          },
          {
            email: 'bob@example.com',
            password: await hashPassword('bob123'),
            name: 'Bob Johnson',
            role: 'user',
            balance: 3000.0
          },
          {
            email: 'admin@example.com',
            password: await hashPassword('admin123'),
            name: 'Admin User',
            role: 'admin',
            balance: 10000.0
          }
        ];

        const stmt = db.prepare('INSERT INTO users (email, password, name, role, balance) VALUES (?, ?, ?, ?, ?)');

        users.forEach(user => {
          stmt.run(user.email, user.password, user.name, user.role, user.balance);
        });

        stmt.finalize();

        // Insert test orders
        const orders = [
          { user_id: 1, product_name: 'Laptop', amount: 1200.0, status: 'completed' },
          { user_id: 1, product_name: 'Mouse', amount: 25.0, status: 'pending' },
          { user_id: 2, product_name: 'Keyboard', amount: 80.0, status: 'completed' },
          { user_id: 2, product_name: 'Monitor', amount: 350.0, status: 'pending' },
          { user_id: 3, product_name: 'Server', amount: 5000.0, status: 'completed' }
        ];

        const orderStmt = db.prepare('INSERT INTO orders (user_id, product_name, amount, status) VALUES (?, ?, ?, ?)');

        orders.forEach(order => {
          orderStmt.run(order.user_id, order.product_name, order.amount, order.status);
        });

        orderStmt.finalize();

        console.log('Database initialized with test data!');
        console.log('\nTest Accounts:');
        console.log('   Alice: alice@example.com / alice123');
        console.log('   Bob:   bob@example.com / bob123');
        console.log('   Admin: admin@example.com / admin123\n');
      }
    });
  });
}

module.exports = { db, initDatabase, hashPassword, verifyPassword };