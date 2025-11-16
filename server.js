const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const winston = require('winston');
const { db, initDatabase, hashPassword, verifyPassword } = require('./database');

const app = express();
const PORT = 3000;

// ════════════════════════════════════════════════════════════════════════
// LOGGING CONFIGURATION
// Location: server.js (Lines 14-28)
// ════════════════════════════════════════════════════════════════════════

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// ════════════════════════════════════════════════════════════════════════
// VULN-006: SECURITY MISCONFIGURATION - CORS
// Location: server.js (Lines 32-52)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: CORS configured with wildcard (*) allows any origin to make
// requests to the API. Combined with credentials:true, this enables
// cross-origin attacks and potential data theft from any malicious website.
//
// app.use(cors({
//   origin: '*',  // Accepts ALL origins - DANGEROUS!
//   credentials: true
// }));

// SECURE CODE (AFTER REMEDIATION):
// Solution: Whitelist specific trusted origins only. Validate origin before
// allowing cross-origin requests.

const allowedOrigins = [
  'https://yourdomain.com',
  'https://www.yourdomain.com',
  'https://app.yourdomain.com'
];

// Add localhost for development
if (process.env.NODE_ENV === 'development') {
  allowedOrigins.push('http://localhost:3000');
  allowedOrigins.push('http://localhost:5173');
}

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `CORS policy does not allow access from origin ${origin}`;
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));

// ════════════════════════════════════════════════════════════════════════
// VULN-006: SECURITY MISCONFIGURATION - Missing Security Headers
// Location: server.js (Lines 76-80)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: Missing security headers leave the application vulnerable to
// clickjacking, XSS, MIME sniffing, and other client-side attacks.
//
// // No security headers configured!

// SECURE CODE (AFTER REMEDIATION):
// Solution: Use Helmet to set security headers automatically

app.use(helmet());

app.use(express.json());

// ════════════════════════════════════════════════════════════════════════
// VULN-006: SECURITY MISCONFIGURATION - No Rate Limiting
// Location: server.js (Lines 92-112)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: No rate limiting allows unlimited requests, enabling brute force
// attacks on authentication endpoints. Attackers can try thousands of
// password combinations per second.
//
// // No rate limiting configured!

// SECURE CODE (AFTER REMEDIATION):
// Solution: Implement rate limiting on sensitive endpoints

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again after 15 minutes'
});

app.use('/api/', generalLimiter);

// Initialize database
initDatabase();

// ════════════════════════════════════════════════════════════════════════
// AUTHENTICATION MIDDLEWARE
// Location: server.js (Lines 120-145)
// ════════════════════════════════════════════════════════════════════════

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  db.get(
    'SELECT users.* FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token = ?',
    [token],
    (err, user) => {
      if (err) {
        logger.error('Authentication error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      req.user = user;
      next();
    }
  );
}

// ════════════════════════════════════════════════════════════════════════
// VULN-003: BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA)
// Location: server.js (Lines 149-165)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: No role verification middleware. Any authenticated user can
// access admin endpoints regardless of their role, leading to privilege
// escalation.
//
// // No role checking implemented!

// SECURE CODE (AFTER REMEDIATION):
// Solution: Create middleware to verify user roles before granting access

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      logger.warn(`Unauthorized access attempt by user ${req.user.id} to ${req.path}`);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

// ════════════════════════════════════════════════════════════════════════
// PUBLIC ENDPOINTS
// Location: server.js (Lines 169-210)
// ════════════════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.json({
    message: 'OWASP 2025 Vulnerable API Demo - REMEDIATED VERSION',
    warning: 'This is the SECURE version with all vulnerabilities fixed',
    endpoints: {
      auth: {
        'POST /register': 'Register a new user',
        'POST /login': 'Login and get token'
      },
      users: {
        'GET /users/:id': 'Get user details (requires auth)',
      },
      orders: {
        'GET /orders/:id': 'Get order details (requires auth)',
        'POST /orders': 'Create a new order (requires auth)'
      },
      admin: {
        'DELETE /users/:id': 'Delete user (admin only)',
        'GET /admin/stats': 'Get system stats (admin only)'
      }
    },
    testAccounts: {
      alice: 'alice@example.com / alice123',
      bob: 'bob@example.com / bob123',
      admin: 'admin@example.com / admin123'
    },
    security: {
      passwordHashing: 'bcrypt (12 rounds)',
      sqlInjection: 'Protected with prepared statements',
      authorization: 'BOLA and BFLA protections enabled',
      rateLimit: 'Enabled on auth endpoints',
      cors: 'Whitelisted origins only',
      headers: 'Security headers via Helmet'
    }
  });
});

// ════════════════════════════════════════════════════════════════════════
// REGISTRATION ENDPOINT
// Location: server.js (Lines 214-255)
// ════════════════════════════════════════════════════════════════════════

app.post('/register', authLimiter, async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Email validation
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Password strength validation
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    // Hash password with bcrypt
    const hashedPassword = await hashPassword(password);

    db.run(
      'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
      [email, hashedPassword, name],
      function(err) {
        if (err) {
          return res.status(400).json({ error: 'User already exists' });
        }

        logger.info(`New user registered: ${email}`);

        res.status(201).json({
          id: this.lastID,
          email,
          name,
          message: 'User registered successfully'
        });
      }
    );
  } catch (err) {
    logger.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════
// VULN-002: SQL INJECTION
// Location: server.js (Lines 259-330)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: SQL query constructed using string concatenation with user input.
// The email parameter is directly interpolated into the query, allowing
// attackers to inject SQL commands (e.g., admin@example.com'--) to bypass
// authentication and gain unauthorized access.
//
// app.post('/login', (req, res) => {
//   const { email, password } = req.body;
//   const hashedPassword = hashPassword(password);
//
//   // String concatenation - SQL INJECTION VULNERABLE!
//   const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${hashedPassword}'`;
//
//   db.get(query, [], (err, user) => {
//     // Attacker can bypass by using: admin@example.com'--
//     // Query becomes: SELECT * FROM users WHERE email = 'admin@example.com'--' AND password = '...'
//     // Everything after -- is commented out!
//   });
// });

// SECURE CODE (AFTER REMEDIATION):
// Solution: Use parameterized queries (prepared statements) where user input
// is passed as parameters, not concatenated into the query string.

app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  // Email validation
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Parameterized query - SQL injection protected!
  db.get(
    'SELECT * FROM users WHERE email = ?',
    [email],
    async (err, user) => {
      if (err) {
        logger.error('Login error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        // Verify password with bcrypt
        const isValid = await verifyPassword(password, user.password);

        if (!isValid) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create session
        const token = crypto.randomBytes(32).toString('hex');

        db.run(
          'INSERT INTO sessions (user_id, token) VALUES (?, ?)',
          [user.id, token],
          (err) => {
            if (err) {
              logger.error('Session creation error:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }

            logger.info(`User logged in: ${user.email}`);

            res.json({
              token,
              user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                balance: user.balance
              }
            });
          }
        );
      } catch (err) {
        logger.error('Password verification error:', err);
        res.status(500).json({ error: 'Login failed' });
      }
    }
  );
});

// ════════════════════════════════════════════════════════════════════════
// VULN-001: BROKEN OBJECT LEVEL AUTHORIZATION (BOLA)
// Location: server.js (Lines 334-375)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: Endpoint returns any order by ID without verifying that the
// authenticated user owns that order. This allows any authenticated user
// to access other users' orders by simply changing the ID parameter,
// leading to unauthorized data exposure.
//
// app.get('/orders/:id', authenticate, (req, res) => {
//   const orderId = req.params.id;
//
//   // No ownership verification!
//   db.get('SELECT * FROM orders WHERE id = ?', [orderId], (err, order) => {
//     if (!order) {
//       return res.status(404).json({ error: 'Order not found' });
//     }
//     // Returns order even if it belongs to another user!
//     res.json(order);
//   });
// });

// SECURE CODE (AFTER REMEDIATION):
// Solution: Verify that the order belongs to the authenticated user before
// returning data. Return 404 instead of 403 to prevent resource enumeration.

app.get('/orders/:id', authenticate, (req, res) => {
  const orderId = req.params.id;

  // Verify ownership by checking user_id matches authenticated user
  db.get(
    'SELECT orders.*, users.name as user_name FROM orders JOIN users ON orders.user_id = users.id WHERE orders.id = ? AND orders.user_id = ?',
    [orderId, req.user.id],
    (err, order) => {
      if (err) {
        logger.error('Order fetch error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!order) {
        // Return 404 instead of 403 to prevent enumeration
        return res.status(404).json({ error: 'Order not found' });
      }

      res.json(order);
    }
  );
});

// Create order
app.post('/orders', authenticate, (req, res) => {
  const { product_name, amount } = req.body;

  if (!product_name || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  db.run(
    'INSERT INTO orders (user_id, product_name, amount) VALUES (?, ?, ?)',
    [req.user.id, product_name, amount],
    function(err) {
      if (err) {
        logger.error('Order creation error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      logger.info(`Order created by user ${req.user.id}: ${product_name}`);

      res.status(201).json({
        id: this.lastID,
        user_id: req.user.id,
        product_name,
        amount,
        status: 'pending'
      });
    }
  );
});

// List user's own orders
app.get('/orders', authenticate, (req, res) => {
  db.all(
    'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, orders) => {
      if (err) {
        logger.error('Orders list error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(orders);
    }
  );
});

// ════════════════════════════════════════════════════════════════════════
// VULN-003: BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA) - Admin Endpoints
// Location: server.js (Lines 430-495)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: Admin endpoints accessible to any authenticated user without
// role verification. This allows regular users to access sensitive system
// statistics and perform administrative actions like deleting users.
//
// app.get('/admin/stats', authenticate, (req, res) => {
//   // No role check - any authenticated user can access!
//   db.all('SELECT COUNT(*) as total_users FROM users', [], ...);
// });
//
// app.delete('/users/:id', authenticate, (req, res) => {
//   // No role check - any user can delete other users!
//   db.run('DELETE FROM users WHERE id = ?', [req.params.id], ...);
// });

// SECURE CODE (AFTER REMEDIATION):
// Solution: Apply requireRole('admin') middleware to verify user has
// admin privileges before granting access.

app.get('/admin/stats', authenticate, requireRole('admin'), (req, res) => {
  db.all('SELECT COUNT(*) as total_users FROM users', [], (err, userCount) => {
    if (err) {
      logger.error('Stats error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    db.all('SELECT COUNT(*) as total_orders FROM orders', [], (err, orderCount) => {
      if (err) {
        logger.error('Stats error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      db.all('SELECT SUM(amount) as total_revenue FROM orders WHERE status = "completed"', [], (err, revenue) => {
        if (err) {
          logger.error('Stats error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }

        res.json({
          total_users: userCount[0].total_users,
          total_orders: orderCount[0].total_orders,
          total_revenue: revenue[0].total_revenue || 0
        });
      });
    });
  });
});

app.delete('/users/:id', authenticate, requireRole('admin'), (req, res) => {
  const userId = req.params.id;

  // Prevent self-deletion
  if (userId == req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) {
      logger.error('User deletion error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.warn(`User ${userId} deleted by admin ${req.user.id}`);
    res.json({ message: 'User deleted successfully' });
  });
});

// Get user details
app.get('/users/:id', authenticate, (req, res) => {
  const userId = req.params.id;

  db.get('SELECT id, email, name, role, balance FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      logger.error('User fetch error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  });
});

// ════════════════════════════════════════════════════════════════════════
// VULN-005: MISHANDLING OF EXCEPTIONAL CONDITIONS (Fail Open)
// Location: server.js (Lines 520-585)
// ════════════════════════════════════════════════════════════════════════

let authServiceAvailable = true;

app.get('/admin/toggle-auth-service', (req, res) => {
  authServiceAvailable = !authServiceAvailable;
  res.json({
    message: `Auth service ${authServiceAvailable ? 'enabled' : 'disabled'}`,
    status: authServiceAvailable
  });
});

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: When the authorization service fails or is unavailable, the
// catch block grants access to premium content instead of denying it.
// This "fail open" behavior allows unauthorized users to bypass access
// controls during service outages or errors.
//
// app.get('/premium-content', authenticate, async (req, res) => {
//   try {
//     if (!authServiceAvailable) {
//       throw new Error('Auth service timeout');
//     }
//
//     const hasPremium = req.user.role === 'admin';
//     if (!hasPremium) {
//       return res.status(403).json({ error: 'Premium required' });
//     }
//
//     res.json({ content: 'SECRET PREMIUM CONTENT' });
//
//   } catch (err) {
//     // FAIL OPEN - Grants access on error!
//     res.json({
//       content: 'SECRET PREMIUM CONTENT',
//       message: 'Auth service down, but here is your content anyway! (VULN!)'
//     });
//   }
// });

// SECURE CODE (AFTER REMEDIATION):
// Solution: Implement "fail closed" - deny access when errors occur.
// Return 503 Service Unavailable instead of granting access.

app.get('/premium-content', authenticate, async (req, res) => {
  try {
    if (!authServiceAvailable) {
      throw new Error('Authorization service unavailable');
    }

    // Verify premium status
    const hasPremium = req.user.role === 'admin';

    if (!hasPremium) {
      return res.status(403).json({
        error: 'Premium subscription required',
        upgrade_url: '/subscription/upgrade'
      });
    }

    // Only grant access if all checks pass
    res.json({
      content: 'SECRET PREMIUM CONTENT',
      message: 'Welcome to premium content!'
    });

  } catch (err) {
    // FAIL CLOSED - Deny access on error!
    logger.error('Premium content access error:', {
      user: req.user.id,
      error: err.message,
      timestamp: new Date().toISOString()
    });

    return res.status(503).json({
      error: 'Service temporarily unavailable',
      message: 'Please try again later',
      retry_after: 60
    });
  }
});

// ════════════════════════════════════════════════════════════════════════
// VULN-006: SECURITY MISCONFIGURATION - Verbose Error Messages
// Location: server.js (Lines 595-620)
// ════════════════════════════════════════════════════════════════════════

// VULNERABLE CODE (BEFORE REMEDIATION):
// Problem: Error handler exposes full stack traces, SQL queries, and
// internal application structure to clients. This information disclosure
// helps attackers understand the application architecture and plan attacks.
//
// app.use((err, req, res, next) => {
//   console.error(err);
//
//   // Exposes everything!
//   res.status(500).json({
//     error: err.message,
//     stack: err.stack,      // Full stack trace revealed!
//     type: err.constructor.name,
//     query: err.sql,        // SQL queries exposed!
//     details: err
//   });
// });

// SECURE CODE (AFTER REMEDIATION):
// Solution: Log errors internally but return generic messages to clients.
// Never expose stack traces or internal details in production.

app.use((err, req, res, next) => {
  // Log full error details internally
  logger.error('Application error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    user: req.user?.id,
    timestamp: new Date().toISOString()
  });

  // Send generic error to client
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(statusCode).json({
    error: message
    // No stack traces, no SQL queries, no internal details!
  });
});

// ════════════════════════════════════════════════════════════════════════
// START SERVER
// ════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
  console.log('\n════════════════════════════════════════════════════════');
  console.log('   OWASP 2025 SECURE API - REMEDIATED VERSION');
  console.log('   ════════════════════════════════════════════════════════');
  console.log(`   Server running on http://localhost:${PORT}`);
  console.log('   All vulnerabilities have been remediated!');
  console.log('   ════════════════════════════════════════════════════════\n');
  console.log('   Security measures implemented:');
  console.log('   - Parameterized SQL queries (No SQL Injection)');
  console.log('   - Object-level authorization (BOLA protected)');
  console.log('   - Function-level authorization (BFLA protected)');
  console.log('   - Bcrypt password hashing (No weak crypto)');
  console.log('   - Fail-closed error handling');
  console.log('   - CORS whitelist, security headers, rate limiting');
  console.log('   ════════════════════════════════════════════════════════\n');
});