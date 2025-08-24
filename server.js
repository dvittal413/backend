require("dotenv").config()
const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { Pool } = require("pg")
const crypto = require("crypto")
const rateLimit = require("express-rate-limit")
const passport = require("passport")
const GoogleStrategy = require("passport-google-oauth20").Strategy
const FacebookStrategy = require("passport-facebook").Strategy
const LinkedInStrategy = require("passport-linkedin-oauth2").Strategy
const session = require("express-session")
const helmet = require("helmet")
const axios = require("axios")
const winston = require("winston")
const { v4: uuidv4 } = require("uuid")
const QRCode = require("qrcode")
const TelegramBot = require("node-telegram-bot-api")
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true })

// Configure logging
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
})

const app = express()
const PORT = process.env.PORT || 5000

// Enhanced security middleware
app.use(helmet())
app.use(express.json({ limit: "10kb" }))

// Database connection with enhanced configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // This bypasses certificate verification
  },
});

// CORS configuration
const corsOptions = {
  origin: "*",
}
app.use(cors(corsOptions))


// Session configuration with enhanced security
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    name: "urlshortener.sid",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
)

// Rate limiting configuration
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: "Too many requests from this IP, please try again later",
  skip: (req) => req.ip === "::1" || req.ip === "127.0.0.1", // Skip for localhost
})

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: "Too many login attempts, please try again later",
})

app.use("/api/", apiLimiter)
app.use("/auth/", authLimiter)

// Initialize passport
app.use(passport.initialize())
app.use(passport.session())

// JWT and Admin secrets
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex")
const ADMIN_SECRET = crypto.randomBytes(32).toString("hex")

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id])
    if (result.rows.length > 0) {
      done(null, result.rows[0])
    } else {
      logger.warn(`User not found during deserialization: ${id}`)
      done(new Error("User not found"), null)
    }
  } catch (error) {
    logger.error(`Deserialization error: ${error.message}`)
    done(error, null)
  }
})

// Configure OAuth strategies
configureOAuthStrategies()

// Database initialization with enhanced schema
const initDB = async () => {
  try {
    await pool.query("SELECT NOW()")
    logger.info("Database connection successful")

    // Updated database schema without email verification columns
    await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255),
    api_token VARCHAR(255) UNIQUE,
    referral_code VARCHAR(20) UNIQUE,
    referred_by INTEGER REFERENCES users(id),
    balance DECIMAL(10,2) DEFAULT 0,
    total_withdrawn DECIMAL(10,2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_oauth BOOLEAN DEFAULT false,
    is_premium BOOLEAN DEFAULT false,
    premium_expires_at TIMESTAMP,
    reset_token VARCHAR(100),
    reset_token_expires TIMESTAMP
  );
      
      CREATE TABLE IF NOT EXISTS links (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        original_url TEXT NOT NULL,
        short_code VARCHAR(200) UNIQUE NOT NULL,
        alias VARCHAR(50),
        title VARCHAR(255),
        description TEXT,
        clicks INTEGER DEFAULT 0,
        unique_clicks INTEGER DEFAULT 0,
        earnings DECIMAL(10,2) DEFAULT 0,
        is_hidden BOOLEAN DEFAULT false,
        password VARCHAR(255),
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_clicked_at TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS clicks (
        id SERIAL PRIMARY KEY,
        link_id INTEGER REFERENCES links(id),
        user_id INTEGER REFERENCES users(id),
        ip_address INET,
        user_agent TEXT,
        country VARCHAR(2),
        city VARCHAR(100),
        device_type VARCHAR(50),
        browser VARCHAR(50),
        os VARCHAR(50),
        referrer TEXT,
        earnings DECIMAL(10,2) DEFAULT 0,
        clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        telegram_share BOOLEAN DEFAULT false
      );
      
      CREATE TABLE IF NOT EXISTS withdrawals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        amount DECIMAL(10,2) NOT NULL,
        publisher_earnings DECIMAL(10,2) NOT NULL,
        referral_earnings DECIMAL(10,2) DEFAULT 0,
        method VARCHAR(50) NOT NULL,
        account_details TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS referral_earnings (
        id SERIAL PRIMARY KEY,
        referrer_id INTEGER REFERENCES users(id),
        referred_id INTEGER REFERENCES users(id),
        amount DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS custom_domains (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        domain VARCHAR(255) UNIQUE NOT NULL,
        verification_code VARCHAR(100) NOT NULL,
        is_verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS premium_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        plan_id VARCHAR(50) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        starts_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_links_user_id ON links(user_id);
      CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);
      CREATE INDEX IF NOT EXISTS idx_clicks_user_id ON clicks(user_id);
      CREATE INDEX IF NOT EXISTS idx_links_short_code ON links(short_code);
      CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);

      CREATE TABLE IF NOT EXISTS telegram_shares (
      id SERIAL PRIMARY KEY,
      link_id INTEGER REFERENCES links(id),
      message_id TEXT NOT NULL,
      chat_id TEXT NOT NULL,
      shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS admin_earnings (
      id SERIAL PRIMARY KEY,
      source VARCHAR(50) NOT NULL, -- 'click', 'withdrawal_fee', etc
      amount DECIMAL(10,2) NOT NULL,
      details TEXT,
      earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
CREATE TABLE IF NOT EXISTS cpm_rates (
    id SERIAL PRIMARY KEY,
    country_code VARCHAR(10) NOT NULL UNIQUE, 
    country_name VARCHAR(100) NOT NULL,
    rate DECIMAL(10, 4) NOT NULL DEFAULT 0.01,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

      INSERT INTO cpm_rates (country_code, country_name, rate) VALUES
      ('US', 'United States', 0.50),
      ('GB', 'United Kingdom', 0.45),
      ('CA', 'Canada', 0.40),
      ('AU', 'Australia', 0.40),
      ('DE', 'Germany', 0.35),
      ('FR', 'France', 0.35),
      ('IN', 'India', 0.10),
      ('PK', 'Pakistan', 0.08),
      ('BD', 'Bangladesh', 0.07),
      ('DEFAULT', 'Default Rate', 0.01)
      ON CONFLICT (country_code) DO NOTHING;

        CREATE INDEX IF NOT EXISTS idx_cpm_rates_country_code ON cpm_rates(country_code);
        CREATE INDEX IF NOT EXISTS idx_cpm_rates_active ON cpm_rates(is_active);

        CREATE OR REPLACE FUNCTION update_cpm_rates_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
-- Drop trigger if it exists
DROP TRIGGER IF EXISTS update_cpm_rates_updated_at ON cpm_rates;

-- Create the trigger
CREATE TRIGGER update_cpm_rates_updated_at
    BEFORE UPDATE ON cpm_rates
    FOR EACH ROW
    EXECUTE FUNCTION update_cpm_rates_updated_at();
            `)

    logger.info("Database initialized successfully")
  } catch (error) {
    logger.error("Database initialization error:", error)
    process.exit(1)
  }
}

// Helper functions
const generateShortCode = () => {
  return crypto.randomBytes(4).toString("hex")
}

const generateApiToken = () => {
  return crypto.randomBytes(20).toString("hex")
}

const generateReferralCode = (username) => {
  return username.toLowerCase().replace(/\s+/g, "") + crypto.randomBytes(2).toString("hex")
}

// Cache for CPM rates to avoid frequent database queries
let cpmRatesCache = {}
let cpmRatesCacheTime = 0
const CPM_CACHE_DURATION = 5 * 60 * 1000 // 5 minutes

// Function to get CPM rates from database with caching
async function getCpmRates() {
  const now = Date.now()

  // Return cached rates if still valid
  if (cpmRatesCacheTime && now - cpmRatesCacheTime < CPM_CACHE_DURATION) {
    return cpmRatesCache
  }

  try {
    const result = await pool.query("SELECT country_code, rate FROM cpm_rates WHERE is_active = true")

    // Convert to object format
    const rates = {}
    result.rows.forEach((row) => {
      rates[row.country_code] = Number.parseFloat(row.rate)
    })

    // Update cache
    cpmRatesCache = rates
    cpmRatesCacheTime = now

    return rates
  } catch (error) {
    logger.error(`Error fetching CPM rates: ${error.message}`)
    // Return fallback rates if database fails
    return {
      US: 0.5,
      GB: 0.45,
      CA: 0.4,
      AU: 0.4,
      DE: 0.35,
      FR: 0.35,
      IN: 0.1,
      PK: 0.08,
      BD: 0.07,
      DEFAULT: 0.01,
    }
  }
}

// Function to clear CPM rates cache
function clearCpmRatesCache() {
  cpmRatesCache = {}
  cpmRatesCacheTime = 0
}

// Define CPM rates per country (configurable via env)
const CPM_RATES = JSON.parse(
  process.env.CPM_RATES ||
  `{
  "US": 0.50,
  "GB": 0.45,
  "CA": 0.40,
  "AU": 0.40,
  "DE": 0.35,
  "FR": 0.35,
  "IN": 0.10,
  "PK": 0.08,
  "BD": 0.07,
  "DEFAULT": 0.01
}`,
)

// Enhanced IP to country lookup with caching
const countryCache = new Map()
const getCountryFromIP = async (ip) => {
  if (countryCache.has(ip)) {
    return countryCache.get(ip)
  }

  try {
    const res = await axios.get(`http://ip-api.com/json/${ip}?fields=countryCode`)
    const countryCode = res.data.countryCode || "DEFAULT"
    countryCache.set(ip, countryCode)
    return countryCode
  } catch (err) {
    logger.error(`Geo lookup failed for IP ${ip}: ${err.message}`)
    return "DEFAULT"
  }
}

// Enhanced device detection
const parseUserAgent = (userAgent) => {
  if (!userAgent) return { device: "Unknown", browser: "Unknown", os: "Unknown" }

  let device = "Desktop"
  if (userAgent.match(/Mobile|Android|iPhone|iPad|iPod/i)) {
    device = "Mobile"
  } else if (userAgent.match(/Tablet|iPad/i)) {
    device = "Tablet"
  }

  let browser = "Unknown"
  if (userAgent.match(/Chrome/i)) browser = "Chrome"
  else if (userAgent.match(/Firefox/i)) browser = "Firefox"
  else if (userAgent.match(/Safari/i)) browser = "Safari"
  else if (userAgent.match(/Edge/i)) browser = "Edge"
  else if (userAgent.match(/Opera|OPR/i)) browser = "Opera"

  let os = "Unknown"
  if (userAgent.match(/Windows/i)) os = "Windows"
  else if (userAgent.match(/Macintosh|Mac OS X/i)) os = "MacOS"
  else if (userAgent.match(/Linux/i)) os = "Linux"
  else if (userAgent.match(/Android/i)) os = "Android"
  else if (userAgent.match(/iPhone|iPad|iPod/i)) os = "iOS"

  return { device, browser, os }
}

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    logger.warn("Attempt to access protected route without token")
    return res.status(401).json({ error: "Access token required" })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn(`Invalid token provided: ${err.message}`)
      return res.status(403).json({ error: "Invalid or expired token" })
    }
    req.user = user
    next()
  })
}

// Admin JWT middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    logger.warn("Admin access attempt without token")
    return res.status(401).json({ error: "Admin token required" })
  }

  jwt.verify(token, ADMIN_SECRET, (err, admin) => {
    if (err) {
      logger.warn(`Invalid admin token: ${err.message}`)
      return res.status(403).json({ error: "Invalid admin token" })
    }
    req.admin = admin
    next()
  })
}

// Configure OAuth strategies
function configureOAuthStrategies() {
  // Google Strategy
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        scope: ["profile", "email"],
        state: true,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value
          const username = profile.displayName || email.split("@")[0]

          // Check if user exists
          const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email])
          let user

          if (userResult.rows.length === 0) {
            // Create new user
            const apiToken = generateApiToken()
            const referralCode = generateReferralCode(username)
            const newUser = await pool.query(
              "INSERT INTO users (username, email, api_token, referral_code, is_oauth) VALUES ($1, $2, $3, $4, $5) RETURNING *",
              [username, email, apiToken, referralCode, true, true],
            )
            user = newUser.rows[0]
            logger.info(`New user created via Google OAuth: ${user.id}`)
          } else {
            user = userResult.rows[0]
            // Update last active
            await pool.query("UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = $1", [user.id])
          }

          return done(null, user)
        } catch (error) {
          logger.error(`Google OAuth error: ${error.message}`)
          return done(error, null)
        }
      },
    ),
  )

  // Facebook Strategy
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: process.env.FACEBOOK_CALLBACK_URL,
        profileFields: ["id", "displayName", "emails"],
        state: true,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value
          const username = profile.displayName || email.split("@")[0]

          // Check if user exists
          const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email])
          let user

          if (userResult.rows.length === 0) {
            // Create new user
            const apiToken = generateApiToken()
            const referralCode = generateReferralCode(username)
            const newUser = await pool.query(
              "INSERT INTO users (username, email, api_token, referral_code, is_oauth) VALUES ($1, $2, $3, $4, $5) RETURNING *",
              [username, email, apiToken, referralCode, true, true],
            )
            user = newUser.rows[0]
            logger.info(`New user created via Facebook OAuth: ${user.id}`)
          } else {
            user = userResult.rows[0]
            // Update last active
            await pool.query("UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = $1", [user.id])
          }

          return done(null, user)
        } catch (error) {
          logger.error(`Facebook OAuth error: ${error.message}`)
          return done(error, null)
        }
      },
    ),
  )

  // LinkedIn Strategy
  passport.use(
    new LinkedInStrategy(
      {
        clientID: process.env.LINKEDIN_CLIENT_ID,
        clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
        callbackURL: process.env.LINKEDIN_CALLBACK_URL,
        scope: ["r_emailaddress", "r_liteprofile"],
        state: true,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value
          const username = profile.displayName || email.split("@")[0]

          // Check if user exists
          const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email])
          let user

          if (userResult.rows.length === 0) {
            // Create new user
            const apiToken = generateApiToken()
            const referralCode = generateReferralCode(username)
            const newUser = await pool.query(
              "INSERT INTO users (username, email, api_token, referral_code, is_oauth) VALUES ($1, $2, $3, $4, $5) RETURNING *",
              [username, email, apiToken, referralCode, true, true],
            )
            user = newUser.rows[0]
            logger.info(`New user created via LinkedIn OAuth: ${user.id}`)
          } else {
            user = userResult.rows[0]
            // Update last active
            await pool.query("UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = $1", [user.id])
          }

          return done(null, user)
        } catch (error) {
          logger.error(`LinkedIn OAuth error: ${error.message}`)
          return done(error, null)
        }
      },
    ),
  )
}

// --- ADMIN ROUTES ---

// Admin registration
app.post("/api/admin/register", async (req, res) => {
  try {
    const { username, email, password } = req.body

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" })
    }

    // Check if admin exists
    const existingAdmin = await pool.query("SELECT * FROM admins WHERE username = $1 OR email = $2", [username, email])
    if (existingAdmin.rows.length > 0) {
      return res.status(400).json({ error: "Admin already exists" })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12)

    // Create admin
    const result = await pool.query(
      "INSERT INTO admins (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email",
      [username, email, hashedPassword],
    )

    const token = jwt.sign({ adminId: result.rows[0].id, username: result.rows[0].username }, ADMIN_SECRET, {
      expiresIn: "1d",
    })

    logger.info(`New admin registered: ${result.rows[0].email}`)
    res.json({
      success: true,
      token,
      admin: result.rows[0],
    })
  } catch (error) {
    logger.error(`Admin registration error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" })
    }

    const result = await pool.query("SELECT * FROM admins WHERE username = $1 OR email = $1", [username])

    if (result.rows.length === 0) {
      logger.warn(`Failed admin login attempt for username: ${username}`)
      return res.status(401).json({ error: "Invalid credentials" })
    }

    const admin = result.rows[0]
    const isMatch = await bcrypt.compare(password, admin.password)

    if (!isMatch) {
      logger.warn(`Failed admin login attempt for username: ${username}`)
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Update last login
    await pool.query("UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [admin.id])

    const token = jwt.sign({ adminId: admin.id, username: admin.username }, ADMIN_SECRET, { expiresIn: "1d" })

    logger.info(`Admin logged in: ${admin.email}`)
    res.json({
      success: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
      },
    })
  } catch (error) {
    logger.error(`Admin login error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin dashboard stats
app.get("/api/admin/dashboard/overview", authenticateAdmin, async (req, res) => {
  try {
    const [userCount, activeUserCount, linkCount, totalClicks, pendingWithdrawals, totalEarnings] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM users"),
      pool.query("SELECT COUNT(*) FROM users WHERE last_active > NOW() - INTERVAL '30 days'"),
      pool.query("SELECT COUNT(*) FROM links"),
      pool.query("SELECT COUNT(*) FROM clicks"),
      pool.query("SELECT COUNT(*) FROM withdrawals WHERE status = 'pending'"),
      pool.query("SELECT SUM(earnings) FROM clicks"),
    ])

    res.json({
      users: Number.parseInt(userCount.rows[0].count),
      activeUsers: Number.parseInt(activeUserCount.rows[0].count),
      links: Number.parseInt(linkCount.rows[0].count),
      clicks: Number.parseInt(totalClicks.rows[0].count),
      pendingWithdrawals: Number.parseInt(pendingWithdrawals.rows[0].count),
      totalEarnings: Number.parseFloat(totalEarnings.rows[0].sum || 0),
    })
  } catch (err) {
    logger.error(`Admin dashboard error: ${err.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin get users with pagination
app.get("/api/admin/users", authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = "" } = req.query
    const offset = (page - 1) * limit

    const query = `
      SELECT 
        id, username, email, is_active, is_premium, 
        balance, total_withdrawn, created_at, last_active
      FROM users 
      WHERE username ILIKE $1 OR email ILIKE $1
      ORDER BY id DESC
      LIMIT $2 OFFSET $3
    `
    const countQuery = `
      SELECT COUNT(*) FROM users WHERE username ILIKE $1 OR email ILIKE $1
    `

    const searchTerm = `%${search}%`
    const [result, countResult] = await Promise.all([
      pool.query(query, [searchTerm, limit, offset]),
      pool.query(countQuery, [searchTerm]),
    ])

    res.json({
      users: result.rows,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Error fetching users: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin get user details
app.get("/api/admin/users/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params

    const userQuery = `
      SELECT 
        id, username, email, is_active, is_premium, 
        balance, total_withdrawn, created_at, last_active,
        referral_code, referred_by
      FROM users 
      WHERE id = $1
    `

    const linksQuery = `
      SELECT COUNT(*) as link_count, SUM(clicks) as total_clicks, SUM(earnings) as total_earnings
      FROM links
      WHERE user_id = $1
    `

    const referralsQuery = `
      SELECT COUNT(*) as referral_count, COALESCE(SUM(amount), 0) as referral_earnings
      FROM referral_earnings
      WHERE referrer_id = $1
    `

    const [userResult, linksResult, referralsResult] = await Promise.all([
      pool.query(userQuery, [id]),
      pool.query(linksQuery, [id]),
      pool.query(referralsQuery, [id]),
    ])

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" })
    }

    const user = userResult.rows[0]
    user.link_stats = linksResult.rows[0]
    user.referral_stats = referralsResult.rows[0]

    res.json(user)
  } catch (error) {
    logger.error(`Error fetching user details: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin toggle user active
app.put("/api/admin/users/:id/toggle-active", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params
    await pool.query("UPDATE users SET is_active = NOT is_active WHERE id = $1", [id])
    logger.info(`Admin ${req.admin.username} toggled active status for user ${id}`)
    res.json({ success: true })
  } catch (error) {
    logger.error(`Error toggling user status: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin withdrawals with pagination
// Admin get withdrawals with pagination
app.get("/api/admin/withdrawals", authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = "all" } = req.query
    const offset = (page - 1) * limit

    let query = `
      SELECT 
        w.*, 
        u.username as user_username,
        u.email as user_email
      FROM withdrawals w
      JOIN users u ON w.user_id = u.id
    `

    let countQuery = "SELECT COUNT(*) FROM withdrawals w"
    const params = []
    const countParams = []

    if (status && status !== "all") {
      query += " WHERE w.status = $1"
      params.push(status)
      countQuery += " WHERE w.status = $1"
      countParams.push(status)
    }

    query += " ORDER BY w.created_at DESC LIMIT $2 OFFSET $3"
    params.push(limit, offset)

    const [result, countResult] = await Promise.all([pool.query(query, params), pool.query(countQuery, countParams)])

    res.json({
      withdrawals: result.rows,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Error fetching withdrawals: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})
// Admin update withdrawal status
app.put("/api/admin/withdrawals/:id/status", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { status } = req.body

    if (!["pending", "approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" })
    }

    await pool.query(
      "UPDATE withdrawals SET status = $1, processed_at = CASE WHEN $1 != 'pending' THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id = $2",
      [status, id],
    )

    logger.info(`Admin ${req.admin.username} updated withdrawal ${id} to ${status}`)
    res.json({ success: true })
  } catch (error) {
    logger.error(`Error updating withdrawal status: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin get announcements
app.get("/api/admin/announcements", authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM announcements ORDER BY created_at DESC")
    res.json(result.rows)
  } catch (error) {
    logger.error(`Error fetching announcements: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin create announcement
app.post("/api/admin/announcements", authenticateAdmin, async (req, res) => {
  try {
    const { title, content, is_active } = req.body

    if (!title || !content) {
      return res.status(400).json({ error: "Title and content are required" })
    }

    const result = await pool.query(
      "INSERT INTO announcements (title, content, is_active) VALUES ($1, $2, $3) RETURNING *",
      [title, content, is_active || true],
    )

    logger.info(`Admin ${req.admin.username} created announcement ${result.rows[0].id}`)
    res.json(result.rows[0])
  } catch (error) {
    logger.error(`Error creating announcement: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin update announcement
app.put("/api/admin/announcements/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { title, content, is_active } = req.body

    const result = await pool.query(
      "UPDATE announcements SET title = $1, content = $2, is_active = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4 RETURNING *",
      [title, content, is_active, id],
    )

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Announcement not found" })
    }

    logger.info(`Admin ${req.admin.username} updated announcement ${id}`)
    res.json(result.rows[0])
  } catch (error) {
    logger.error(`Error updating announcement: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin delete announcement
app.delete("/api/admin/announcements/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params
    await pool.query("DELETE FROM announcements WHERE id = $1", [id])
    logger.info(`Admin ${req.admin.username} deleted announcement ${id}`)
    res.json({ success: true })
  } catch (error) {
    logger.error(`Error deleting announcement: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin get links with pagination
app.get("/api/admin/links", authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = "" } = req.query
    const offset = (page - 1) * limit

    const query = `
      SELECT 
        l.*, 
        u.username as user_username,
        u.email as user_email
      FROM links l
      JOIN users u ON l.user_id = u.id
      WHERE l.original_url ILIKE $1 OR l.short_code ILIKE $1 OR u.username ILIKE $1 OR u.email ILIKE $1
      ORDER BY l.created_at DESC
      LIMIT $2 OFFSET $3
    `
    const countQuery = `
      SELECT COUNT(*)
      FROM links l
      JOIN users u ON l.user_id = u.id
      WHERE l.original_url ILIKE $1 OR l.short_code ILIKE $1 OR u.username ILIKE $1 OR u.email ILIKE $1
    `

    const searchTerm = `%${search}%`
    const [result, countResult] = await Promise.all([
      pool.query(query, [searchTerm, limit, offset]),
      pool.query(countQuery, [searchTerm]),
    ])

    res.json({
      links: result.rows,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Error fetching links: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin delete link
app.delete("/api/admin/links/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params
    await pool.query("DELETE FROM links WHERE id = $1", [id])
    logger.info(`Admin ${req.admin.username} deleted link ${id}`)
    res.json({ success: true })
  } catch (error) {
    logger.error(`Error deleting link: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin get clicks with pagination
app.get("/api/admin/clicks", authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, link_id } = req.query
    const offset = (page - 1) * limit

    let query = `
      SELECT 
        c.*, 
        l.short_code,
        l.original_url,
        u.username as user_username
      FROM clicks c
      JOIN links l ON c.link_id = l.id
      JOIN users u ON l.user_id = u.id
    `

    let countQuery = "SELECT COUNT(*) FROM clicks"
    const params = []
    const countParams = []

    if (link_id) {
      query += " WHERE c.link_id = $1"
      params.push(link_id)
      countQuery += " WHERE link_id = $1"
      countParams.push(link_id)
    }

    query += " ORDER BY c.clicked_at DESC LIMIT $2 OFFSET $3"
    params.push(limit, offset)

    const [result, countResult] = await Promise.all([pool.query(query, params), pool.query(countQuery, countParams)])

    res.json({
      clicks: result.rows,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Error fetching clicks: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Admin get stats
app.get("/api/admin/stats", authenticateAdmin, async (req, res) => {
  try {
    const { period = "30d" } = req.query
    let interval = "30 DAY"

    switch (period) {
      case "7d":
        interval = "7 DAY"
        break
      case "30d":
        interval = "30 DAY"
        break
      case "90d":
        interval = "90 DAY"
        break
      case "1y":
        interval = "1 YEAR"
        break
      default:
        interval = "30 DAY"
    }

    const clicksQuery = `
      SELECT 
        DATE_TRUNC('day', clicked_at) as date,
        COUNT(*) as clicks,
        SUM(earnings) as earnings
      FROM clicks
      WHERE clicked_at > NOW() - INTERVAL '${interval}'
      GROUP BY DATE_TRUNC('day', clicked_at)
      ORDER BY date
    `

    const usersQuery = `
      SELECT 
        DATE_TRUNC('day', created_at) as date,
        COUNT(*) as users
      FROM users
      WHERE created_at > NOW() - INTERVAL '${interval}'
      GROUP BY DATE_TRUNC('day', created_at)
      ORDER BY date
    `

    const topLinksQuery = `
      SELECT 
        l.id,
        l.short_code,
        l.original_url,
        u.username,
        COUNT(c.id) as clicks,
        SUM(c.earnings) as earnings
      FROM links l
      JOIN users u ON l.user_id = u.id
      JOIN clicks c ON l.id = c.link_id
      WHERE c.clicked_at > NOW() - INTERVAL '${interval}'
      GROUP BY l.id, u.username
      ORDER BY clicks DESC
      LIMIT 10
    `

    const topCountriesQuery = `
      SELECT 
        country,
        COUNT(*) as clicks,
        SUM(earnings) as earnings
      FROM clicks
      WHERE clicked_at > NOW() - INTERVAL '${interval}' AND country IS NOT NULL
      GROUP BY country
      ORDER BY clicks DESC
      LIMIT 10
    `

    const [clicksResult, usersResult, topLinksResult, topCountriesResult] = await Promise.all([
      pool.query(clicksQuery),
      pool.query(usersQuery),
      pool.query(topLinksQuery),
      pool.query(topCountriesQuery),
    ])

    res.json({
      clicks: clicksResult.rows,
      users: usersResult.rows,
      topLinks: topLinksResult.rows,
      topCountries: topCountriesResult.rows,
    })
  } catch (error) {
    logger.error(`Error fetching admin stats: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// CPM Management API Endpoints
app.get("/api/admin/cpm-rates", authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM cpm_rates ORDER BY country_code ASC")
    res.json(result.rows)
  } catch (error) {
    logger.error(`Error fetching CPM rates: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// CREATE CPM rate
app.post("/api/admin/cpm-rates", authenticateAdmin, async (req, res) => {
  try {
    const { country_code, country_name, rate, is_active = true } = req.body

    if (!country_code || !country_name || rate === undefined) {
      return res.status(400).json({ error: "Country code, country name and rate are required" })
    }
    const code = String(country_code).toUpperCase().trim()
    const name = String(country_name).trim()
    const numRate = Number.parseFloat(rate)
    if (Number.isNaN(numRate) || numRate < 0) {
      return res.status(400).json({ error: "Rate must be a valid positive number" })
    }

    const exists = await pool.query("SELECT id FROM cpm_rates WHERE country_code = $1", [code])
    if (exists.rows.length > 0) {
      return res.status(400).json({ error: "CPM rate for this country already exists" })
    }

    const result = await pool.query(
      "INSERT INTO cpm_rates (country_code, country_name, rate, is_active) VALUES ($1,$2,$3,$4) RETURNING *",
      [code, name, numRate, !!is_active]
    )

    clearCpmRatesCache?.() // safe if defined in your file
    return res.json(result.rows[0])
  } catch (error) {
    console.error("Error creating CPM rate:", error)
    return res.status(500).json({ error: "Server error" })
  }
})

// UPDATE CPM rate (partial-friendly)
app.put("/api/admin/cpm-rates/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { country_code, country_name, rate, is_active } = req.body

    const current = await pool.query("SELECT * FROM cpm_rates WHERE id = $1", [id])
    if (current.rows.length === 0) {
      return res.status(404).json({ error: "CPM rate not found" })
    }

    const prev = current.rows[0]
    const newCode = (country_code ? String(country_code) : prev.country_code).toUpperCase().trim()
    const newName = country_name !== undefined ? String(country_name).trim() : prev.country_name
    const newRate =
      rate !== undefined ? Number.parseFloat(rate) : Number.parseFloat(prev.rate)
    const newActive = is_active !== undefined ? !!is_active : prev.is_active

    if (!newCode || !newName) {
      return res.status(400).json({ error: "Country code and country name are required" })
    }
    if (Number.isNaN(newRate) || newRate < 0) {
      return res.status(400).json({ error: "Rate must be a valid positive number" })
    }

    // ensure unique code (except this row)
    const dup = await pool.query(
      "SELECT id FROM cpm_rates WHERE country_code = $1 AND id != $2",
      [newCode, id]
    )
    if (dup.rows.length) {
      return res.status(400).json({ error: "CPM rate for this country already exists" })
    }

    const result = await pool.query(
      `UPDATE cpm_rates
       SET country_code = $1, country_name = $2, rate = $3, is_active = $4, updated_at = CURRENT_TIMESTAMP
       WHERE id = $5
       RETURNING *`,
      [newCode, newName, newRate, newActive, id]
    )

    clearCpmRatesCache?.()
    return res.json(result.rows[0])
  } catch (error) {
    console.error("Error updating CPM rate:", error)
    return res.status(500).json({ error: "Server error" })
  }
})



app.delete("/api/admin/cpm-rates/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params

    const result = await pool.query("DELETE FROM cpm_rates WHERE id = $1 RETURNING country_code, rate", [id])

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "CPM rate not found" })
    }

    // Clear cache when rates are updated
    clearCpmRatesCache()

    logger.info(`Admin ${req.admin.username} deleted CPM rate ${id}: ${result.rows[0].country_code}`)
    res.json({ success: true })
  } catch (error) {
    logger.error(`Error deleting CPM rate: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

app.post("/api/admin/cpm-rates/bulk-update", authenticateAdmin, async (req, res) => {
  try {
    const { rates } = req.body

    if (!rates || !Array.isArray(rates) || rates.length === 0) {
      return res.status(400).json({ error: "Rates array is required" })
    }

    const client = await pool.connect()
    try {
      await client.query("BEGIN")

      const results = []
      for (const rateData of rates) {
        const { id, country_code, rate, is_active } = rateData

        if (!country_code || rate === undefined) {
          throw new Error(`Invalid data for rate: ${JSON.stringify(rateData)}`)
        }

        if (isNaN(rate) || Number.parseFloat(rate) < 0) {
          throw new Error(`Invalid rate value: ${rate}`)
        }

        if (id) {
          // Update existing rate
          const result = await client.query(
            `UPDATE cpm_rates 
             SET country_code = $1, rate = $2, is_active = $3, updated_at = CURRENT_TIMESTAMP 
             WHERE id = $4 
             RETURNING *`,
            [country_code.toUpperCase(), Number.parseFloat(rate), is_active, id],
          )
          if (result.rows.length > 0) {
            results.push(result.rows[0])
          }
        } else {
          // Create new rate
          const result = await client.query(
            "INSERT INTO cpm_rates (country_code, rate, is_active) VALUES ($1, $2, $3) RETURNING *",
            [country_code.toUpperCase(), Number.parseFloat(rate), is_active],
          )
          results.push(result.rows[0])
        }
      }

      await client.query("COMMIT")

      // Clear cache when rates are updated
      clearCpmRatesCache()

      logger.info(`Admin ${req.admin.username} bulk updated ${results.length} CPM rates`)
      res.json({ success: true, updated: results })
    } catch (error) {
      await client.query("ROLLBACK")
      throw error
    } finally {
      client.release()
    }
  } catch (error) {
    logger.error(`Error bulk updating CPM rates: ${error.message}`)
    res.status(500).json({ error: error.message || "Server error" })
  }
})

app.post("/api/admin/cpm-rates/clear-cache", authenticateAdmin, async (req, res) => {
  try {
    clearCpmRatesCache()
    logger.info(`Admin ${req.admin.username} cleared CPM rates cache`)
    res.json({ success: true, message: "CPM rates cache cleared" })
  } catch (error) {
    logger.error(`Error clearing CPM cache: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

app.get("/api/admin/cpm-rates/stats", authenticateAdmin, async (req, res) => {
  try {
    const [totalRates, activeRates, topCountries, recentClicks] = await Promise.all([
      pool.query("SELECT COUNT(*) as total FROM cpm_rates"),
      pool.query("SELECT COUNT(*) as active FROM cpm_rates WHERE is_active = true"),
      pool.query(`
        SELECT 
          c.country,
          COUNT(*) as clicks,
          SUM(c.earnings) as total_earnings,
          AVG(c.earnings) as avg_cpm
        FROM clicks c
        WHERE c.clicked_at > NOW() - INTERVAL '30 days' AND c.country IS NOT NULL
        GROUP BY c.country
        ORDER BY clicks DESC
        LIMIT 10
      `),
      pool.query(`
        SELECT 
          DATE(clicked_at) as date,
          COUNT(*) as clicks,
          SUM(earnings) as earnings
        FROM clicks
        WHERE clicked_at > NOW() - INTERVAL '7 days'
        GROUP BY DATE(clicked_at)
        ORDER BY date DESC
      `),
    ])

    res.json({
      totalRates: Number.parseInt(totalRates.rows[0].total),
      activeRates: Number.parseInt(activeRates.rows[0].active),
      topCountries: topCountries.rows,
      recentClicks: recentClicks.rows,
      cacheStatus: {
        cached: cpmRatesCacheTime > 0,
        lastUpdated: cpmRatesCacheTime ? new Date(cpmRatesCacheTime).toISOString() : null,
        cacheAge: cpmRatesCacheTime ? Date.now() - cpmRatesCacheTime : 0,
      },
    })
  } catch (error) {
    logger.error(`Error fetching CPM stats: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// --- USER ROUTES ---

// Social Auth Routes
app.get("/auth/google", passport.authenticate("google"))

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  const token = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: "1d" })
  res.redirect(`${process.env.FRONTEND_URL}/auth-callback?token=${token}`)
})

app.get("/auth/facebook", passport.authenticate("facebook"))

app.get("/auth/facebook/callback", passport.authenticate("facebook", { failureRedirect: "/login" }), (req, res) => {
  const token = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: "1d" })
  res.redirect(`${process.env.FRONTEND_URL}/auth-callback?token=${token}`)
})

app.get("/auth/linkedin", passport.authenticate("linkedin"))

app.get("/auth/linkedin/callback", passport.authenticate("linkedin", { failureRedirect: "/login" }), (req, res) => {
  const token = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: "1d" })
  res.redirect(`${process.env.FRONTEND_URL}/auth-callback?token=${token}`)
})

// Check auth status
app.get("/auth/status", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ authenticated: true, user: req.user })
  } else {
    res.json({ authenticated: false })
  }
})

// Logout
app.get("/auth/logout", (req, res) => {
  req.logout()
  res.json({ success: true })
})

// Register// Updated registration route without email verification
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, referralCode } = req.body

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" })
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" })
    }

    // Check if user exists
    const existingUser = await pool.query("SELECT * FROM users WHERE username = $1 OR email = $2", [username, email])
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username or email already exists" })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12)
    const apiToken = generateApiToken()
    const userReferralCode = generateReferralCode(username)

    let referredBy = null
    if (referralCode) {
      const referrer = await pool.query("SELECT id FROM users WHERE referral_code = $1", [referralCode])
      if (referrer.rows.length > 0) {
        referredBy = referrer.rows[0].id
      }
    }

    // Create user
    const result = await pool.query(
      `INSERT INTO users 
       (username, email, password, api_token, referral_code, referred_by) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, username, email, referral_code, is_premium`,
      [username, email, hashedPassword, apiToken, userReferralCode, referredBy],
    )

    const user = result.rows[0]
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1d" })

    res.json({
      success: true,
      token,
      user,
    })
  } catch (error) {
    logger.error(`Registration error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})
// Verify email

// Login

// Updated login route without email verification check
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" })
    }

    const result = await pool.query("SELECT * FROM users WHERE username = $1 OR email = $1", [username])

    if (result.rows.length === 0) {
      logger.warn(`Failed login attempt for username: ${username}`)
      return res.status(400).json({ error: "Invalid credentials" })
    }

    const user = result.rows[0]

    if (!user.is_active) {
      return res.status(403).json({ error: "Account is disabled" })
    }

    const validPassword = await bcrypt.compare(password, user.password)

    if (!validPassword) {
      logger.warn(`Failed login attempt for username: ${username}`)
      return res.status(400).json({ error: "Invalid credentials" })
    }

    // Update last active
    await pool.query("UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = $1", [user.id])

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1d" })

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        balance: user.balance,
        referral_code: user.referral_code,
        is_premium: user.is_premium,
      },
    })
  } catch (error) {
    logger.error(`Login error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Forgot password
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ error: "Email is required" })
    }

    const result = await pool.query("SELECT id, email FROM users WHERE email = $1", [email])

    if (result.rows.length === 0) {
      return res.json({ success: true, message: "If email exists, a reset link has been sent" })
    }

    const user = result.rows[0]
    const resetToken = crypto.randomBytes(20).toString("hex")
    const resetTokenExpires = new Date(Date.now() + 3600000) // 1 hour from now

    await pool.query("UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3", [
      resetToken,
      resetTokenExpires,
      user.id,
    ])

    // In production, send email with reset link
    logger.info(`Password reset token for ${user.email}: ${resetToken}`)

    res.json({ success: true, message: "If email exists, a reset link has been sent" })
  } catch (error) {
    logger.error(`Forgot password error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Reset password
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body

    if (!token || !password) {
      return res.status(400).json({ error: "Token and new password are required" })
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" })
    }

    const userResult = await pool.query("SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()", [
      token,
    ])

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired token" })
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    await pool.query("UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2", [
      hashedPassword,
      userResult.rows[0].id,
    ])

    res.json({ success: true, message: "Password updated successfully" })
  } catch (error) {
    logger.error(`Reset password error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Dashboard
app.get("/api/dashboard", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId

    const [userStats, todayStats, monthlyStats, announcements, referralStats] = await Promise.all([
      pool.query(
        `
        SELECT 
          u.balance,
          u.total_withdrawn,
          u.referral_code,
          u.is_premium,
          COALESCE(SUM(l.clicks), 0) as total_views,
          COALESCE(SUM(l.earnings), 0) as total_earnings,
          COALESCE(ref_earnings.total, 0) as referral_earnings,
          COUNT(DISTINCT l.id) as total_links
        FROM users u
        LEFT JOIN links l ON u.id = l.user_id
        LEFT JOIN (
          SELECT referrer_id, SUM(amount) as total 
          FROM referral_earnings 
          WHERE referrer_id = $1 
          GROUP BY referrer_id
        ) ref_earnings ON u.id = ref_earnings.referrer_id
        WHERE u.id = $1
        GROUP BY u.id, ref_earnings.total
        `,
        [userId],
      ),
      pool.query(
        `
        SELECT 
          COALESCE(SUM(c.earnings), 0) as today_earnings,
          COUNT(c.id) as today_views
        FROM clicks c
        JOIN links l ON c.link_id = l.id
        WHERE l.user_id = $1 AND DATE(c.clicked_at) = CURRENT_DATE
        `,
        [userId],
      ),
      pool.query(
        `
        SELECT 
          COALESCE(SUM(c.earnings), 0) as monthly_earnings,
          COUNT(c.id) as monthly_views
        FROM clicks c
        JOIN links l ON c.link_id = l.id
        WHERE l.user_id = $1 AND DATE_TRUNC('month', c.clicked_at) = DATE_TRUNC('month', CURRENT_DATE)
        `,
        [userId],
      ),
      pool.query("SELECT * FROM announcements WHERE is_active = true ORDER BY created_at DESC LIMIT 5"),
      pool.query(
        `
        SELECT COUNT(*) as referral_count, COALESCE(SUM(amount), 0) as referral_earnings
        FROM referral_earnings
        WHERE referrer_id = $1
        `,
        [userId],
      ),
    ])

    res.json({
      user: userStats.rows[0],
      today: todayStats.rows[0],
      monthly: monthlyStats.rows[0],
      announcements: announcements.rows,
      referralStats: referralStats.rows[0],
    })
  } catch (error) {
    logger.error(`Dashboard error for user ${userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Link Management
app.post("/api/shorten", authenticateToken, async (req, res) => {
  try {
    const { url, alias, title, description, password, expiresAt } = req.body
    const userId = req.user.userId

    if (!url) {
      return res.status(400).json({ error: "URL is required" })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch (err) {
      return res.status(400).json({ error: "Invalid URL format" })
    }

    let shortCode = alias || generateShortCode()

    // Check if alias already exists
    const existingLink = await pool.query("SELECT * FROM links WHERE short_code = $1", [shortCode])
    if (existingLink.rows.length > 0) {
      if (alias) {
        return res.status(400).json({ error: "Alias already exists" })
      }
      shortCode = generateShortCode()
    }

    // Check if user has reached link limit (if not premium)
    if (!req.user.is_premium) {
      const linkCount = await pool.query("SELECT COUNT(*) FROM links WHERE user_id = $1", [userId])
      if (Number.parseInt(linkCount.rows[0].count) >= 100) {
        return res.status(403).json({
          error: "Free account link limit reached (100 links)",
          upgradeRequired: true,
        })
      }
    }

    // Parse expiration date
    let expiresAtDate = null
    if (expiresAt) {
      expiresAtDate = new Date(expiresAt)
      if (isNaN(expiresAtDate.getTime())) {
        return res.status(400).json({ error: "Invalid expiration date" })
      }
    }

    const result = await pool.query(
      `INSERT INTO links 
       (user_id, original_url, short_code, alias, title, description, password, expires_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
       RETURNING *`,
      [userId, url, shortCode, alias, title, description, password, expiresAtDate],
    )

    const link = result.rows[0]
    const shortUrl = `${process.env.BASE_URL || "https://dvshortylinks.com"}/${shortCode}`

    // Generate QR code
    let qrCode = null
    try {
      qrCode = await QRCode.toDataURL(shortUrl)
    } catch (err) {
      logger.error(`QR code generation error: ${err.message}`)
    }

    res.json({
      success: true,
      shortenedUrl: shortUrl,
      qrCode,
      link,
    })
  } catch (error) {
    logger.error(`Shorten error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Get all links with pagination
app.get("/api/links", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const { page = 1, limit = 10, search = "", hidden } = req.query
    const offset = (page - 1) * limit

    let query = `
      SELECT 
        id, original_url, short_code, alias, title, 
        description, clicks, earnings, is_hidden,
        created_at, expires_at, password IS NOT NULL as has_password
      FROM links 
      WHERE user_id = $1
    `

    let countQuery = "SELECT COUNT(*) FROM links WHERE user_id = $1"
    const params = [userId]
    const countParams = [userId]

    if (hidden === "true" || hidden === "false") {
      query += " AND is_hidden = $2"
      params.push(hidden === "true")
      countQuery += " AND is_hidden = $2"
      countParams.push(hidden === "true")
    }

    if (search) {
      query += " AND (original_url ILIKE $2 OR short_code ILIKE $2 OR alias ILIKE $2 OR title ILIKE $2)"
      params.push(`%${search}%`)
      countQuery += " AND (original_url ILIKE $2 OR short_code ILIKE $2 OR alias ILIKE $2 OR title ILIKE $2)"
      countParams.push(`%${search}%`)
    }

    query += " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
    params.push(limit, offset)

    const [result, countResult] = await Promise.all([pool.query(query, params), pool.query(countQuery, countParams)])

    // Generate short URLs with the correct domain
    const links = result.rows.map((link) => ({
      ...link,
      short_url: `${process.env.BASE_URL || "https://dvshortylinks.com"}/${link.short_code}`,
    }))

    res.json({
      links,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Links fetch error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Get link details
app.get("/api/links/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.user.userId

    const result = await pool.query(
      `
      SELECT 
        id, original_url, short_code, alias, title, 
        description, clicks, earnings, is_hidden,
        created_at, expires_at, password IS NOT NULL as has_password
      FROM links 
      WHERE id = $1 AND user_id = $2
      `,
      [id, userId],
    )

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Link not found" })
    }

    const link = result.rows[0]
    link.short_url = `${process.env.BASE_URL || "https://dvshortylinks.com"}/${link.short_code}`

    // Generate QR code
    try {
      link.qr_code = await QRCode.toDataURL(link.short_url)
    } catch (err) {
      logger.error(`QR code generation error: ${err.message}`)
      link.qr_code = null
    }

    res.json(link)
  } catch (error) {
    logger.error(`Link details error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Update link
app.put("/api/links/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.user.userId
    const { title, description, is_hidden, password } = req.body

    const result = await pool.query(
      `
      UPDATE links 
      SET 
        title = COALESCE($1, title),
        description = COALESCE($2, description),
        is_hidden = COALESCE($3, is_hidden),
        password = CASE WHEN $4 = '' THEN NULL ELSE COALESCE($4, password) END
      WHERE id = $5 AND user_id = $6
      RETURNING *
      `,
      [title, description, is_hidden, password, id, userId],
    )

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Link not found" })
    }

    res.json(result.rows[0])
  } catch (error) {
    logger.error(`Link update error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Delete link
app.delete("/api/links/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.user.userId

    const result = await pool.query("DELETE FROM links WHERE id = $1 AND user_id = $2 RETURNING id", [id, userId])

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Link not found" })
    }

    res.json({ success: true })
  } catch (error) {
    logger.error(`Link delete error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Bulk link actions
app.post("/api/links/bulk-action", authenticateToken, async (req, res) => {
  try {
    const { action, linkIds } = req.body
    const userId = req.user.userId

    if (!action || !linkIds || !Array.isArray(linkIds) || linkIds.length === 0) {
      return res.status(400).json({ error: "Invalid request" })
    }

    let query
    switch (action) {
      case "hide":
        query = "UPDATE links SET is_hidden = true WHERE id = ANY($1) AND user_id = $2"
        break
      case "unhide":
        query = "UPDATE links SET is_hidden = false WHERE id = ANY($1) AND user_id = $2"
        break
      case "delete":
        query = "DELETE FROM links WHERE id = ANY($1) AND user_id = $2"
        break
      default:
        return res.status(400).json({ error: "Invalid action" })
    }

    const result = await pool.query(query, [linkIds, userId])

    res.json({
      success: true,
      affectedCount: result.rowCount,
    })
  } catch (error) {
    logger.error(`Bulk link action error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Link statistics
app.get("/api/links/:id/stats", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.user.userId
    const { period = "7d" } = req.query

    // Verify link belongs to user
    const linkCheck = await pool.query("SELECT id FROM links WHERE id = $1 AND user_id = $2", [id, userId])

    if (linkCheck.rows.length === 0) {
      return res.status(404).json({ error: "Link not found" })
    }

    let interval = "7 DAY"
    switch (period) {
      case "24h":
        interval = "1 DAY"
        break
      case "7d":
        interval = "7 DAY"
        break
      case "30d":
        interval = "30 DAY"
        break
      case "90d":
        interval = "90 DAY"
        break
      case "all":
        interval = "100 YEAR"
        break
    }

    // Click statistics by date
    const clicksByDate = await pool.query(
      `
      SELECT 
        DATE_TRUNC('day', clicked_at) as date,
        COUNT(*) as clicks,
        SUM(earnings) as earnings
      FROM clicks
      WHERE link_id = $1 AND clicked_at > NOW() - INTERVAL '${interval}'
      GROUP BY DATE_TRUNC('day', clicked_at)
      ORDER BY date
      `,
      [id],
    )

    // Click statistics by country
    const clicksByCountry = await pool.query(
      `
      SELECT 
        country,
        COUNT(*) as clicks,
        SUM(earnings) as earnings
      FROM clicks
      WHERE link_id = $1 AND clicked_at > NOW() - INTERVAL '${interval}' AND country IS NOT NULL
      GROUP BY country
      ORDER BY clicks DESC
      LIMIT 10
      `,
      [id],
    )

    // Click statistics by referrer
    const clicksByReferrer = await pool.query(
      `
      SELECT 
        CASE WHEN referrer = '' OR referrer IS NULL THEN 'Direct' ELSE referrer END as referrer,
        COUNT(*) as clicks,
        SUM(earnings) as earnings
      FROM clicks
      WHERE link_id = $1 AND clicked_at > NOW() - INTERVAL '${interval}'
      GROUP BY CASE WHEN referrer = '' OR referrer IS NULL THEN 'Direct' ELSE referrer END
      ORDER BY clicks DESC
      LIMIT 10
      `,
      [id],
    )

    // Device statistics
    const clicksByDevice = await pool.query(
      `
      SELECT 
        device_type,
        COUNT(*) as clicks,
        SUM(earnings) as earnings
      FROM clicks
      WHERE link_id = $1 AND clicked_at > NOW() - INTERVAL '${interval}' AND device_type IS NOT NULL
      GROUP BY device_type
      ORDER BY clicks DESC
      `,
      [id],
    )

    // Recent clicks
    const recentClicks = await pool.query(
      `
      SELECT 
        clicked_at,
        country,
        city,
        device_type,
        browser,
        os,
        referrer,
        earnings
      FROM clicks
      WHERE link_id = $1
      ORDER BY clicked_at DESC
      LIMIT 10
      `,
      [id],
    )

    res.json({
      clicksByDate: clicksByDate.rows,
      clicksByCountry: clicksByCountry.rows,
      clicksByReferrer: clicksByReferrer.rows,
      clicksByDevice: clicksByDevice.rows,
      recentClicks: recentClicks.rows,
    })
  } catch (error) {
    logger.error(`Link stats error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Recent activity for Admin Dashboard
app.get("/api/admin/recent-activity", authenticateAdmin, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, Number.parseInt(req.query.limit || "20", 10)));

    // Build a unified feed across tables
    const { rows } = await pool.query(
      `
      SELECT * FROM (
        -- New users
        SELECT 
          'user_registered' AS type,
          CONCAT('New user registered: ', COALESCE(username, 'Unknown')) AS description,
          EXTRACT(EPOCH FROM created_at) * 1000 AS ts_ms
        FROM users

        UNION ALL

        -- New links
        SELECT
          'link_created' AS type,
          CONCAT('Link created (id ', id, '): ', COALESCE(title, short_code)) AS description,
          EXTRACT(EPOCH FROM created_at) * 1000 AS ts_ms
        FROM links

        UNION ALL

        -- Clicks (recent)
        SELECT
          'click' AS type,
          CONCAT('Click from ', COALESCE(country, 'Unknown'), ' on link ', link_id) AS description,
          EXTRACT(EPOCH FROM clicked_at) * 1000 AS ts_ms
        FROM clicks

        UNION ALL

        -- Withdrawal requests
        SELECT
          'withdrawal_request' AS type,
          CONCAT('Withdrawal requested: $', amount::text, ' (', status, ') by user ', user_id) AS description,
          EXTRACT(EPOCH FROM created_at) * 1000 AS ts_ms
        FROM withdrawals

        UNION ALL

        -- Withdrawals processed (approved/paid)
        SELECT
          'withdrawal_processed' AS type,
          CONCAT('Withdrawal ', status, ': $', amount::text, ' for user ', user_id) AS description,
          EXTRACT(EPOCH FROM updated_at) * 1000 AS ts_ms
        FROM withdrawals
        WHERE status IN ('approved','paid')
      ) AS feed
      ORDER BY ts_ms DESC
      LIMIT $1
      `,
      [limit],
    )

    // Normalize payload
    const data = rows.map(r => ({
      type: r.type,
      description: r.description,
      timestamp: Number(r.ts_ms) || Date.now(),
    }))

    res.json(data)
  } catch (err) {
    logger?.error?.(`recent-activity error: ${err.message}`)
    res.status(500).json({ error: "Server error" })
  }
})


// Redirect endpoint
app.get("/:shortCode", async (req, res) => {
  try {
    const { shortCode } = req.params

    // Check for custom domain first
    const domain = req.headers.host
    if (domain !== (process.env.BASE_URL || "https://dvshortylinks.com/").replace(/https?:\/\//, "")) {
      const customDomain = await pool.query(
        "SELECT user_id FROM custom_domains WHERE domain = $1 AND is_verified = true",
        [domain],
      )

      if (customDomain.rows.length > 0) {
        const userId = customDomain.rows[0].user_id
        const linkResult = await pool.query("SELECT * FROM links WHERE short_code = $1 AND user_id = $2", [
          shortCode,
          userId,
        ])

        if (linkResult.rows.length > 0) {
          return handleLinkRedirect(linkResult.rows[0], req, res)
        }
      }
    }

    // Standard lookup
    const linkResult = await pool.query("SELECT * FROM links WHERE short_code = $1", [shortCode])

    if (linkResult.rows.length === 0) {
      return res.status(404).send("Short link not found")
    }

    return handleLinkRedirect(linkResult.rows[0], req, res)
  } catch (error) {
    logger.error(`Short redirect error: ${error.message}`)
    return res.status(500).send("Something went wrong")
  }
})

// Password-protected link access
app.post("/:shortCode/access", async (req, res) => {
  try {
    const { shortCode } = req.params
    const { password } = req.body

    if (!password) {
      return res.status(400).json({ error: "Password is required" })
    }

    const linkResult = await pool.query("SELECT * FROM links WHERE short_code = $1 AND password IS NOT NULL", [
      shortCode,
    ])

    if (linkResult.rows.length === 0) {
      return res.status(404).json({ error: "Link not found or not password protected" })
    }

    const link = linkResult.rows[0]
    const isMatch = await bcrypt.compare(password, link.password)

    if (!isMatch) {
      return res.status(403).json({ error: "Incorrect password" })
    }

    // Create a temporary access token
    const accessToken = jwt.sign({ linkId: link.id, access: "password" }, JWT_SECRET, { expiresIn: "5m" })

    res.json({ success: true, accessToken })
  } catch (error) {
    logger.error(`Password access error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})



// API Routes
app.get("/api/user/api-token", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const result = await pool.query("SELECT api_token FROM users WHERE id = $1", [userId])
    res.json({ apiToken: result.rows[0].api_token })
  } catch (error) {
    logger.error(`API token error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

app.post("/api/generate-api-token", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const apiToken = generateApiToken()
    await pool.query("UPDATE users SET api_token = $1 WHERE id = $2", [apiToken, userId])
    res.json({ apiToken })
  } catch (error) {
    logger.error(`Generate API token error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

app.get("/api", async (req, res) => {
  try {
    const { api, url, alias, format } = req.query

    if (!api || !url) {
      return res.status(400).json({ status: "error", message: "API token and URL are required" })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch (err) {
      return res.status(400).json({ status: "error", message: "Invalid URL format" })
    }

    const userResult = await pool.query("SELECT id, is_premium FROM users WHERE api_token = $1", [api])
    if (userResult.rows.length === 0) {
      return res.status(401).json({ status: "error", message: "Invalid API token" })
    }

    const userId = userResult.rows[0].id
    const isPremium = userResult.rows[0].is_premium

    // Check link limit for non-premium users
    if (!isPremium) {
      const linkCount = await pool.query("SELECT COUNT(*) FROM links WHERE user_id = $1", [userId])
      if (Number.parseInt(linkCount.rows[0].count) >= 100) {
        return res.status(403).json({
          status: "error",
          message: "Free account link limit reached (100 links)",
          upgradeRequired: true,
        })
      }
    }

    let shortCode = alias || generateShortCode()

    // Check if alias already exists
    const existingLink = await pool.query("SELECT * FROM links WHERE short_code = $1", [shortCode])
    if (existingLink.rows.length > 0) {
      if (alias) {
        return res.status(400).json({ status: "error", message: "Alias already exists" })
      }
      shortCode = generateShortCode()
    }

    await pool.query("INSERT INTO links (user_id, original_url, short_code, alias) VALUES ($1, $2, $3, $4)", [
      userId,
      url,
      shortCode,
      alias,
    ])

    const shortenedUrl = `${process.env.BASE_URL || "https://dvshortylinks.com"}/${shortCode}`

    if (format === "text") {
      res.send(shortenedUrl)
    } else {
      res.json({ status: "success", shortenedUrl })
    }
  } catch (error) {
    logger.error(`API error: ${error.message}`)
    res.status(500).json({ status: "error", message: "Server error" })
  }
})

// Mass shorten API
app.post("/api/mass-shorten", authenticateToken, async (req, res) => {
  try {
    const { urls } = req.body
    const userId = req.user.userId

    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ error: "URLs array is required" })
    }

    // Check link limit for non-premium users
    if (!req.user.is_premium) {
      const linkCount = await pool.query("SELECT COUNT(*) FROM links WHERE user_id = $1", [userId])
      if (Number.parseInt(linkCount.rows[0].count) + urls.length > 100) {
        return res.status(403).json({
          error: "Free account link limit reached (100 links)",
          upgradeRequired: true,
        })
      }
    }

    const results = []
    for (const url of urls) {
      try {
        new URL(url) // Validate URL format
        const shortCode = generateShortCode()
        await pool.query("INSERT INTO links (user_id, original_url, short_code) VALUES ($1, $2, $3)", [
          userId,
          url.trim(),
          shortCode,
        ])
        results.push({
          originalUrl: url,
          shortenedUrl: `${process.env.BASE_URL || "https://dvshortylinks.com"}/${shortCode}`,
          shortCode,
          success: true,
        })
      } catch (err) {
        results.push({
          originalUrl: url,
          error: "Invalid URL",
          success: false,
        })
      }
    }

    res.json({ success: true, results })
  } catch (error) {
    logger.error(`Mass shorten error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Payment Routes
app.get("/api/payments", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const { page = 1, limit = 10 } = req.query
    const offset = (page - 1) * limit

    const [result, countResult] = await Promise.all([
      pool.query("SELECT * FROM withdrawals WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", [
        userId,
        limit,
        offset,
      ]),
      pool.query("SELECT COUNT(*) FROM withdrawals WHERE user_id = $1", [userId]),
    ])

    res.json({
      withdrawals: result.rows,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Payments error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Withdraw request
app.post("/api/withdraw", authenticateToken, async (req, res) => {
  try {
    const { amount, method, accountDetails } = req.body
    const userId = req.user.userId

    // Validation
    if (!amount || !method || !accountDetails) {
      return res.status(400).json({ error: "All fields are required" })
    }

    if (isNaN(amount)) {
      return res.status(400).json({ error: "Invalid amount" })
    }

    const numAmount = Number.parseFloat(amount)

    // Check minimum withdrawal amount
    const minWithdrawal = req.user.is_premium ? 5 : 10 // Premium users have lower minimum
    if (numAmount < minWithdrawal) {
      return res.status(400).json({
        error: `Minimum withdrawal amount is $${minWithdrawal}`,
        minWithdrawal,
      })
    }

    // Check user balance
    const userResult = await pool.query("SELECT balance FROM users WHERE id = $1", [userId])
    if (userResult.rows[0].balance < numAmount) {
      return res.status(400).json({ error: "Insufficient balance" })
    }

    // Create withdrawal request
    await pool.query(
      `INSERT INTO withdrawals 
       (user_id, amount, publisher_earnings, method, account_details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, numAmount, numAmount, method, accountDetails],
    )

    // Deduct from user balance
    await pool.query("UPDATE users SET balance = balance - $1 WHERE id = $2", [numAmount, userId])

    logger.info(`User ${userId} requested withdrawal of $${numAmount}`)
    res.json({ success: true, message: "Withdrawal request submitted" })
  } catch (error) {
    logger.error(`Withdrawal error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Referral Routes
app.get("/api/referrals", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const { page = 1, limit = 10 } = req.query
    const offset = (page - 1) * limit

    const [result, countResult] = await Promise.all([
      pool.query(
        `SELECT 
          u.username, u.email, u.created_at, 
          COALESCE(SUM(re.amount), 0) as earnings,
          COUNT(l.id) as links_created,
          COALESCE(SUM(l.clicks), 0) as total_clicks
         FROM users u
         LEFT JOIN referral_earnings re ON u.id = re.referred_id AND re.referrer_id = $1
         LEFT JOIN links l ON u.id = l.user_id
         WHERE u.referred_by = $1
         GROUP BY u.id
         ORDER BY u.created_at DESC
         LIMIT $2 OFFSET $3`,
        [userId, limit, offset],
      ),
      pool.query("SELECT COUNT(*) FROM users WHERE referred_by = $1", [userId]),
    ])

    res.json({
      referrals: result.rows,
      total: Number.parseInt(countResult.rows[0].count),
      page: Number.parseInt(page),
      limit: Number.parseInt(limit),
    })
  } catch (error) {
    logger.error(`Referrals error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Statistics Routes
app.get("/api/statistics", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const { period = "30d" } = req.query

    let interval = "30 DAY"
    switch (period) {
      case "7d":
        interval = "7 DAY"
        break
      case "30d":
        interval = "30 DAY"
        break
      case "90d":
        interval = "90 DAY"
        break
      case "1y":
        interval = "1 YEAR"
        break
      case "all":
        interval = "10 YEAR"
        break
      default:
        interval = "30 DAY"
    }

    // Daily statistics
    const dailyStats = await pool.query(
      `
      SELECT 
        DATE(c.clicked_at) as date,
        COUNT(c.id) as views,
        COALESCE(SUM(c.earnings), 0) as link_earnings,
        COALESCE(AVG(c.earnings), 0) as daily_cpm,
        COALESCE(ref.referral_earnings, 0) as referral_earnings
      FROM clicks c
      JOIN links l ON c.link_id = l.id
      LEFT JOIN (
        SELECT 
          DATE(created_at) as date,
          SUM(amount) as referral_earnings
        FROM referral_earnings 
        WHERE referrer_id = $1
        GROUP BY DATE(created_at)
      ) ref ON DATE(c.clicked_at) = ref.date
      WHERE l.user_id = $1 
        AND c.clicked_at > NOW() - INTERVAL '${interval}'
      GROUP BY DATE(c.clicked_at), ref.referral_earnings
      ORDER BY DATE(c.clicked_at) DESC
      `,
      [userId],
    )

    // Country statistics
    const countryStats = await pool.query(
      `
      SELECT 
        c.country,
        COUNT(c.id) as views,
        COALESCE(SUM(c.earnings), 0) as earnings
      FROM clicks c
      JOIN links l ON c.link_id = l.id
      WHERE l.user_id = $1 
        AND c.clicked_at > NOW() - INTERVAL '${interval}'
        AND c.country IS NOT NULL
      GROUP BY c.country
      ORDER BY views DESC
      LIMIT 10
      `,
      [userId],
    )

    // Device statistics
    const deviceStats = await pool.query(
      `
      SELECT 
        c.device_type,
        COUNT(c.id) as views,
        COALESCE(SUM(c.earnings), 0) as earnings
      FROM clicks c
      JOIN links l ON c.link_id = l.id
      WHERE l.user_id = $1 
        AND c.clicked_at > NOW() - INTERVAL '${interval}'
        AND c.device_type IS NOT NULL
      GROUP BY c.device_type
      ORDER BY views DESC
      `,
      [userId],
    )

    // Top links
    const topLinks = await pool.query(
      `
      SELECT 
        l.id,
        l.short_code,
        l.alias,
        l.title,
        COUNT(c.id) as views,
        COALESCE(SUM(c.earnings), 0) as earnings
      FROM links l
      LEFT JOIN clicks c ON l.id = c.link_id
      WHERE l.user_id = $1 
        AND (c.clicked_at > NOW() - INTERVAL '${interval}' OR c.id IS NULL)
      GROUP BY l.id
      ORDER BY views DESC
      LIMIT 5
      `,
      [userId],
    )

    res.json({
      dailyStats: dailyStats.rows,
      countryStats: countryStats.rows,
      deviceStats: deviceStats.rows,
      topLinks: topLinks.rows,
    })
  } catch (error) {
    logger.error(`Statistics error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Settings Routes
app.get("/api/settings", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const result = await pool.query("SELECT username, email, is_premium, referral_code FROM users WHERE id = $1", [
      userId,
    ])

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" })
    }

    // Get custom domains
    const domainsResult = await pool.query("SELECT domain, is_verified FROM custom_domains WHERE user_id = $1", [
      userId,
    ])

    res.json({
      ...result.rows[0],
      customDomains: domainsResult.rows,
    })
  } catch (error) {
    logger.error(`Settings error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Update password
app.put("/api/settings/password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body
    const userId = req.user.userId

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Current and new password are required" })
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: "New password must be at least 8 characters" })
    }

    const userResult = await pool.query("SELECT password FROM users WHERE id = $1", [userId])
    const validPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password)

    if (!validPassword) {
      return res.status(400).json({ error: "Current password is incorrect" })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12)
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, userId])

    res.json({ success: true, message: "Password updated successfully" })
  } catch (error) {
    logger.error(`Password update error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Update email
// Updated email update route without verification
app.put("/api/settings/email", authenticateToken, async (req, res) => {
  try {
    const { newEmail, password } = req.body
    const userId = req.user.userId

    if (!newEmail || !password) {
      return res.status(400).json({ error: "New email and password are required" })
    }

    // Verify password
    const userResult = await pool.query("SELECT password FROM users WHERE id = $1", [userId])
    const validPassword = await bcrypt.compare(password, userResult.rows[0].password)

    if (!validPassword) {
      return res.status(400).json({ error: "Password is incorrect" })
    }

    // Check if email already exists
    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1 AND id != $2", [newEmail, userId])
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already exists" })
    }

    await pool.query("UPDATE users SET email = $1 WHERE id = $2", [newEmail, userId])

    res.json({
      success: true,
      message: "Email updated successfully",
    })
  } catch (error) {
    logger.error(`Email update error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Update username
app.put("/api/settings/username", authenticateToken, async (req, res) => {
  try {
    const { newUsername, password } = req.body
    const userId = req.user.userId

    if (!newUsername || !password) {
      return res.status(400).json({ error: "New username and password are required" })
    }

    // Verify password
    const userResult = await pool.query("SELECT password FROM users WHERE id = $1", [userId])
    const validPassword = await bcrypt.compare(password, userResult.rows[0].password)

    if (!validPassword) {
      return res.status(400).json({ error: "Password is incorrect" })
    }

    const existingUser = await pool.query("SELECT id FROM users WHERE username = $1 AND id != $2", [
      newUsername,
      userId,
    ])
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username already exists" })
    }

    await pool.query("UPDATE users SET username = $1 WHERE id = $2", [newUsername, userId])

    res.json({ success: true, message: "Username updated successfully" })
  } catch (error) {
    logger.error(`Username update error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Custom domains
app.post("/api/settings/domains", authenticateToken, async (req, res) => {
  try {
    const { domain } = req.body
    const userId = req.user.userId

    if (!domain) {
      return res.status(400).json({ error: "Domain is required" })
    }

    // Simple domain validation
    if (!domain.match(/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/)) {
      return res.status(400).json({ error: "Invalid domain format" })
    }

    // Check if domain already exists
    const existingDomain = await pool.query("SELECT id FROM custom_domains WHERE domain = $1", [domain])
    if (existingDomain.rows.length > 0) {
      return res.status(400).json({ error: "Domain already registered" })
    }

    // Generate verification code
    const verificationCode = crypto.randomBytes(8).toString("hex")

    const result = await pool.query(
      `INSERT INTO custom_domains 
       (user_id, domain, verification_code) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [userId, domain, verificationCode],
    )

    // In production, you would instruct the user to add a TXT record with this code
    logger.info(`User ${userId} added domain ${domain}, verification code: ${verificationCode}`)

    res.json({
      success: true,
      domain: result.rows[0],
      verificationInstructions: `Please add a TXT record to your domain with the value: urlshort-verification=${verificationCode}`,
    })
  } catch (error) {
    logger.error(`Add domain error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Verify domain
app.post("/api/settings/domains/:id/verify", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.user.userId

    // Get domain info
    const domainResult = await pool.query(
      "SELECT domain, verification_code FROM custom_domains WHERE id = $1 AND user_id = $2",
      [id, userId],
    )

    if (domainResult.rows.length === 0) {
      return res.status(404).json({ error: "Domain not found" })
    }

    const domain = domainResult.rows[0].domain
    const verificationCode = domainResult.rows[0].verification_code

    // In a real application, you would verify the TXT record here
    // For this example, we'll just mark it as verified
    await pool.query("UPDATE custom_domains SET is_verified = true WHERE id = $1", [id])

    res.json({ success: true, message: "Domain verified successfully" })
  } catch (error) {
    logger.error(`Verify domain error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Delete domain
app.delete("/api/settings/domains/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const userId = req.user.userId

    const result = await pool.query("DELETE FROM custom_domains WHERE id = $1 AND user_id = $2 RETURNING domain", [
      id,
      userId,
    ])

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Domain not found" })
    }

    res.json({ success: true, message: "Domain removed successfully" })
  } catch (error) {
    logger.error(`Delete domain error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Premium subscription
app.post("/api/premium/subscribe", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    const { planId } = req.body

    if (!planId || !["monthly", "yearly"].includes(planId)) {
      return res.status(400).json({ error: "Invalid plan" })
    }

    // In a real application, you would process payment here
    // For this example, we'll just create the subscription

    const amount = planId === "monthly" ? 9.99 : 99.99
    const startsAt = new Date()
    const expiresAt = new Date()
    expiresAt.setMonth(expiresAt.getMonth() + (planId === "monthly" ? 1 : 12))

    // Create subscription
    await pool.query(
      `INSERT INTO premium_subscriptions 
       (user_id, plan_id, amount, starts_at, expires_at) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, planId, amount, startsAt, expiresAt],
    )

    // Update user premium status
    await pool.query("UPDATE users SET is_premium = true, premium_expires_at = $1 WHERE id = $2", [expiresAt, userId])

    res.json({ success: true, message: "Premium subscription activated" })
  } catch (error) {
    logger.error(`Premium subscribe error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Premium cancel
app.post("/api/premium/cancel", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId

    // In a real application, you would cancel any recurring payments
    // For this example, we'll just mark the subscription as cancelled
    await pool.query("UPDATE premium_subscriptions SET status = 'cancelled' WHERE user_id = $1 AND status = 'active'", [
      userId,
    ])

    // User will remain premium until their subscription expires
    res.json({
      success: true,
      message: "Premium subscription will remain active until the end of the current billing period",
    })
  } catch (error) {
    logger.error(`Premium cancel error for user ${req.user.userId}: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Contact form
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: "All fields are required" })
    }

    // In a real application, you would send an email or store in database
    logger.info(`Contact form submission from ${email}: ${subject} - ${message}`)

    res.json({ success: true, message: "Message sent successfully" })
  } catch (error) {
    logger.error(`Contact error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`, { stack: err.stack })
  res.status(500).json({ error: "Internal server error" })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Not found" })
})

// Track Telegram shares
app.post("/api/track-telegram", async (req, res) => {
  const { shortCode, messageId, chatId } = req.body

  await pool.query(
    `INSERT INTO telegram_shares 
     (link_id, message_id, chat_id) 
     VALUES (
       (SELECT id FROM links WHERE short_code = $1), 
       $2, $3
     )`,
    [shortCode, messageId, chatId],
  )

  res.json({ success: true })
})

// Telegram bot handler
bot.on("message", async (msg) => {
  if (msg.text && msg.text.includes(process.env.BASE_URL)) {
    const shortCode = msg.text.split("/").pop()
    await pool.query(
      `UPDATE links SET telegram_shares = telegram_shares + 1 
       WHERE short_code = $1`,
      [shortCode],
    )
  }
})

// Add to backend/index.js
// Admin revenue endpoint
app.get("/api/admin/revenue", authenticateAdmin, async (req, res) => {
  const [total, today, users, links] = await Promise.all([
    pool.query("SELECT SUM(amount) as total FROM admin_earnings"),
    pool.query("SELECT SUM(amount) as total FROM admin_earnings WHERE earned_at >= CURRENT_DATE"),
    pool.query("SELECT SUM(amount) as total FROM admin_earnings WHERE source = 'withdrawal_fee'"),
    pool.query(`
      SELECT l.short_code, l.clicks, l.earnings, u.username
      FROM links l JOIN users u ON l.user_id = u.id
      ORDER BY l.earnings DESC LIMIT 10
    `),
  ])

  res.json({
    totalEarnings: Number.parseFloat(total.rows[0].total || 0),
    todayEarnings: Number.parseFloat(today.rows[0].total || 0),
    userEarnings: Number.parseFloat(users.rows[0].total || 0),
    topLinks: links.rows,
  })
})


// Redirect endpoint with proper ad handling
app.get("/:shortCode", async (req, res) => {
  try {
    const { shortCode } = req.params;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get("User-Agent") || "";
    const referrer = req.get("Referrer") || "";

    // Check for custom domain first
    const domain = req.headers.host;
    if (domain !== (process.env.BASE_URL || "https://dvshortylinks.com/").replace(/https?:\/\//, "")) {
      const customDomain = await pool.query(
        "SELECT user_id FROM custom_domains WHERE domain = $1 AND is_verified = true",
        [domain],
      );

      if (customDomain.rows.length > 0) {
        const userId = customDomain.rows[0].user_id;
        const linkResult = await pool.query(
          "SELECT * FROM links WHERE short_code = $1 AND user_id = $2",
          [shortCode, userId],
        );

        if (linkResult.rows.length > 0) {
          return handleLinkRedirect(linkResult.rows[0], req, res);
        }
      }
    }

    // Standard lookup
    const linkResult = await pool.query("SELECT * FROM links WHERE short_code = $1", [shortCode]);

    if (linkResult.rows.length === 0) {
      return res.status(404).send("Short link not found");
    }

    return handleLinkRedirect(linkResult.rows[0], req, res);
  } catch (error) {
    logger.error(`Short redirect error: ${error.message}`);
    return res.status(500).send("Something went wrong");
  }
});

// Add the resolve endpoint
app.get("/api/resolve/:shortCode", async (req, res) => {
  try {
    const { shortCode } = req.params

    const linkResult = await pool.query("SELECT * FROM links WHERE short_code = $1", [shortCode])

    if (linkResult.rows.length === 0) {
      return res.status(404).json({ error: "Short URL not found" })
    }

    const link = linkResult.rows[0]
    
    // Check if link is hidden or expired
    if (link.is_hidden) {
      return res.status(403).json({ error: "This link is currently hidden" })
    }

    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return res.status(410).json({ error: "This link has expired" })
    }

    res.json({ 
      originalUrl: link.original_url,
      shortCode: link.short_code,
      title: link.title,
      created: link.created_at
    })
  } catch (error) {
    logger.error(`Resolve short URL error: ${error.message}`)
    res.status(500).json({ error: "Server error" })
  }
})


// Enhanced handleLinkRedirect function
async function handleLinkRedirect(link, req, res) {
  try {
    // Check if link is hidden
    if (link.is_hidden) {
      return res.status(403).send("This link is currently hidden.");
    }

    // Check if link is expired
    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return res.status(410).send("This link has expired.");
    }

    // Check if password protected
    if (link.password) {
      // Check for access token in cookie
      const accessToken = req.cookies[`access_${link.short_code}`];
      if (accessToken) {
        try {
          jwt.verify(accessToken, JWT_SECRET);
          // Token is valid, proceed to redirect with ads
          return serveAdPageAndRedirect(link, req, res);
        } catch (err) {
          // Token is invalid or expired, show password form
        }
      }
      return showPasswordForm(link, res);
    }

    // Serve ad page and redirect
    return serveAdPageAndRedirect(link, req, res);
  } catch (error) {
    logger.error(`Link redirect handling error: ${error.message}`);
    return res.status(500).send("Something went wrong");
  }
}

// Serve ad page and handle redirect
async function serveAdPageAndRedirect(link, req, res) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get("User-Agent") || "";
  const referrer = req.get("Referrer") || "";

  try {
    // Parse device info
    const { device, browser, os } = parseUserAgent(userAgent);

    // Get country from IP
    const country = await getCountryFromIP(ip);
    const cpmRates = await getCpmRates();
    const cpmRate = cpmRates[country] || cpmRates.DEFAULT || 0.01;
    
    // Calculate earnings (per click)
    const earnings = cpmRate / 1000; // CPM is per 1000 views, so divide by 1000

    // Calculate user and admin shares (70% user, 30% admin)
    const userEarnings = earnings * 0.7;
    const adminEarnings = earnings * 0.3;

    // Record click in database
    await pool.query(
      `INSERT INTO clicks 
       (link_id, user_id, ip_address, user_agent, referrer, country, device_type, browser, os, earnings) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [link.id, link.user_id, ip, userAgent, referrer, country, device, browser, os, userEarnings],
    );

    // Update link stats
    await pool.query(
      "UPDATE links SET clicks = clicks + 1, earnings = earnings + $1, last_clicked_at = NOW() WHERE id = $2",
      [userEarnings, link.id],
    );

    // Update user balance
    await pool.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [userEarnings, link.user_id]);

    // Track admin earnings
    await pool.query(
      `INSERT INTO admin_earnings (source, amount, details)
       VALUES ('click', $1, $2)`,
      [adminEarnings, `Link: ${link.short_code}, User: ${link.user_id}`],
    );

    // Handle referral earnings (10% commission)
    const userResult = await pool.query("SELECT referred_by FROM users WHERE id = $1", [link.user_id]);
    if (userResult.rows[0]?.referred_by) {
      const referralEarnings = userEarnings * 0.1;
      await pool.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [
        referralEarnings,
        userResult.rows[0].referred_by,
      ]);

      await pool.query("INSERT INTO referral_earnings (referrer_id, referred_id, amount) VALUES ($1, $2, $3)", [
        userResult.rows[0].referred_by,
        link.user_id,
        referralEarnings,
      ]);
    }

   // Inside serveAdPageAndRedirect(link, req, res) AFTER your DB updates:
const adMode = (process.env.AD_MODE || "NETWORK").toUpperCase();
const safeUrl = String(link.original_url).replace(/"/g, "&quot;");

const networkHtml = `<!doctype html>
<html><head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Redirecting…</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
    .wrap{max-width:480px;width:92%;background:rgba(255,255,255,.12);backdrop-filter:blur(10px);border-radius:18px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.2)}
    h1{margin:0 0 6px;font-size:22px}
    .ad{background:#fff;color:#000;border-radius:12px;min-height:200px;display:flex;align-items:center;justify-content:center;margin:14px 0;padding:8px}
    .meta{opacity:.9;font-size:14px;margin-top:6px}
    .cta{display:flex;gap:10px;margin-top:14px}
    .btn{flex:1;background:#ff4757;border:none;color:#fff;padding:12px 14px;border-radius:10px;font-weight:600;cursor:pointer}
    .btn:hover{filter:brightness(1.07)}
    .timer{font-size:14px;margin-top:6px}
    a {color:#fff}
  </style>

  <!-- Google AdSense (optional) -->
  ${
    process.env.ADSENSE_CLIENT
      ? `<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${process.env.ADSENSE_CLIENT}" crossorigin="anonymous"></script>`
      : ""
  }
</head><body>
  <div class="wrap">
    <h1>Getting your link ready…</h1>
    <div class="ad">
      <!-- Insert your ad tag below (choose ONE network) -->
      <!-- AdSense example -->
      ${
        process.env.ADSENSE_CLIENT && process.env.ADSENSE_SLOT
          ? `<ins class="adsbygoogle" style="display:block" data-ad-client="${process.env.ADSENSE_CLIENT}" data-ad-slot="${process.env.ADSENSE_SLOT}" data-ad-format="auto" data-full-width-responsive="true"></ins>
             <script>(adsbygoogle=window.adsbygoogle||[]).push({});</script>`
          : ""
      }
      <!-- Propeller example -->
      ${
        process.env.PROPELLER_ZONE_ID
          ? `<script data-cfasync="false" async src="//upgulpinon.com/1?zoneid=${process.env.PROPELLER_ZONE_ID}"></script>`
          : ""
      }
      ${
        !process.env.ADSENSE_CLIENT && !process.env.PROPELLER_ZONE_ID
          ? `<div style="text-align:center">
               <h3>Advertisement</h3>
               <p>Add your AdSense or Propeller tag in server env vars.</p>
             </div>`
          : ""
      }
    </div>

    <div class="meta">Please wait while we redirect you.</div>
    <div class="timer" id="t">Redirecting in <b>10</b>s</div>
    <div class="cta">
      <button class="btn" id="skip">Skip</button>
      <a class="btn" style="text-decoration:none;text-align:center;background:#2ed573" href="${safeUrl}">Go now</a>
    </div>
  </div>

  <script>
    // Track view (your endpoint already exists)
    fetch('/api/track-ad-view',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({linkId:'${link.id}',shortCode:'${link.short_code}',timestamp:new Date().toISOString()})
    });

    let s=10, el=document.getElementById('t');
    const int=setInterval(()=>{ s--; el.innerHTML='Redirecting in <b>'+s+'</b>s'; if(s===0){clearInterval(int); location.href="${safeUrl}";}},1000);
    document.getElementById('skip').onclick=()=>{clearInterval(int); location.href="${safeUrl}";}
  </script>
</body></html>`;

const quizHtml = `<!doctype html>
<html><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Answer 3 quick questions</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial;background:#0e0f1a;color:#fff;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
    .wrap{max-width:520px;width:92%;background:#14162b;border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:24px;box-shadow:0 10px 40px rgba(0,0,0,.35)}
    h1{font-size:20px;margin:0 0 10px}
    .q{background:#1b1f3a;border-radius:14px;padding:16px;margin:12px 0}
    .opts{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
    .opt{background:#293056;border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:12px;cursor:pointer;text-align:center}
    .opt:hover{filter:brightness(1.1)}
    .status{display:flex;justify-content:space-between;align-items:center;margin-top:12px;font-size:14px;opacity:.9}
    .go{margin-top:14px;display:flex;gap:10px}
    .btn{flex:1;background:#2ed573;border:none;color:#001b0a;padding:12px 14px;border-radius:10px;font-weight:700;cursor:pointer}
    .btn[disabled]{opacity:.5;cursor:not-allowed}
    .skip{background:#ff4757;color:#fff}
    .ad{background:#fff;color:#000;border-radius:10px;padding:10px;margin:8px 0;text-align:center}
  </style>
</head><body>
  <div class="wrap">
    <h1>Just 3 quick math questions</h1>
    <div id="quiz"></div>

    <!-- Optional: still show an ad block above/below quiz -->
    <div class="ad">Your ad tag can also be placed here.</div>

    <div class="status"><div>Answered: <b id="done">0</b>/3</div><div id="t">Redirect in <b>10</b>s</div></div>
    <div class="go">
      <button class="btn" id="continue" disabled>Continue</button>
      <button class="btn skip" id="skip">Skip</button>
    </div>
  </div>

  <script>
    const dest="${safeUrl}";
    let s=10, answered=0;
    const tEl=document.getElementById('t'), doneEl=document.getElementById('done'), btn=document.getElementById('continue');

    function rnd(n){return Math.floor(Math.random()*n)+1}
    function makeQ(type){
      let a=rnd(9), b=rnd(9), q='', ans=0;
      if(type==='add'){ans=a+b; q=\`\${a} + \${b} = ?\`;}
      if(type==='sub'){if(a<b){[a,b]=[b,a]} ans=a-b; q=\`\${a} - \${b} = ?\`;}
      if(type==='div'){ans=a; q=\`\${a*b} ÷ \${b} = ?\`;} // integer result
      const opts=[ans, ans+1, Math.max(0,ans-1)];
      // per your request, treat ANY choice as correct (we won't validate).
      return {q, opts};
    }

    const qs=[makeQ('add'), makeQ('sub'), makeQ('div')];
    const quiz=document.getElementById('quiz');
    qs.forEach((x,i)=>{
      const box=document.createElement('div'); box.className='q';
      box.innerHTML='<div>Q'+(i+1)+': '+x.q+'</div>';
      const opts=document.createElement('div'); opts.className='opts';
      x.opts.forEach(v=>{
        const b=document.createElement('div'); b.className='opt'; b.textContent=v;
        b.onclick=()=>{
          if(b.dataset.done) return;
          b.dataset.done='1';
          answered++; doneEl.textContent=answered;
          box.style.outline='2px solid #2ed573';
          // unlock continue when all 3 answered AND timer done
          if(answered>=3 && s<=0) btn.disabled=false;
        };
        opts.appendChild(b);
      });
      box.appendChild(opts); quiz.appendChild(box);
    });

    // Track view
    fetch('/api/track-ad-view',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({linkId:'${link.id}',shortCode:'${link.short_code}',timestamp:new Date().toISOString()})
    });

    const int=setInterval(()=>{ s--; tEl.innerHTML='Redirect in <b>'+s+'</b>s';
      if(s<=0){ clearInterval(int); if(answered>=3) btn.disabled=false; else tEl.innerHTML='Answer questions to continue'; }
    },1000);

    btn.onclick=()=>{ location.href=dest; };
    document.getElementById('skip').onclick=()=>{ location.href=dest; };
  </script>
</body></html>`;

const adTemplate = adMode === "QUIZ" ? quizHtml : networkHtml;
res.send(adTemplate);


  } catch (error) {
    logger.error(`Ad redirect error: ${error.message}`);
    // If something fails, redirect directly without ads
    return res.redirect(link.original_url);
  }
}

// Password form function
function showPasswordForm(link, res) {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Password Required - dvshortylinks.com</title>
      <style>
        body { 
          font-family: Arial, sans-serif; 
          text-align: center; 
          margin-top: 100px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
        }
        .container {
          background: rgba(255, 255, 255, 0.1);
          backdrop-filter: blur(10px);
          border-radius: 20px;
          padding: 40px;
          max-width: 400px;
          width: 90%;
        }
        input {
          width: 100%;
          padding: 12px;
          margin: 10px 0;
          border: none;
          border-radius: 5px;
          font-size: 16px;
        }
        button {
          width: 100%;
          padding: 12px;
          background: #007bff;
          color: white;
          border: none;
          border-radius: 5px;
          cursor: pointer;
          font-size: 16px;
        }
        button:hover {
          background: #0056b3;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>🔒 This link is password protected</h2>
        <form id="passwordForm">
          <input type="password" name="password" placeholder="Enter password" required>
          <button type="submit">Submit</button>
        </form>
      </div>
      <script>
        document.getElementById('passwordForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const password = e.target.password.value;
          const response = await fetch('/${link.short_code}/access', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
          });
          const data = await response.json();
          if (data.success) {
            // Set cookie with access token (valid for 5 minutes)
            document.cookie = 'access_${link.short_code}=' + data.accessToken + '; path=/; max-age=300';
            window.location.reload();
          } else {
            alert(data.error || 'Incorrect password');
          }
        });
      </script>
    </body>
    </html>
  `);
}

// Track ad views
app.post("/api/track-ad-view", async (req, res) => {
  try {
    const { linkId, shortCode, timestamp } = req.body;
    
    // You can implement ad view tracking here
    // This is where you'd integrate with your ad network
    logger.info(`Ad viewed for link ${linkId} (${shortCode}) at ${timestamp}`);
    
    res.json({ success: true });
  } catch (error) {
    logger.error(`Ad tracking error: ${error.message}`);
    res.status(500).json({ error: "Ad tracking failed" });
  }
});



// (Keep this LAST so it only serves real front-end routes)
const path = require("path");


// static assets
app.use(express.static(path.join(__dirname, 'client/build')));

// SPA fallback — Express 5 safe
app.get(/^(?!\/api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});
// Start server after DB initialization
const startServer = async () => {
  try {
    await initDB()
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`)
    })
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`)
    process.exit(1)
  }
}

startServer()
