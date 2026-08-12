PRAGMA foreign_keys = ON;

-- Users & Roles

CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  username       TEXT UNIQUE NOT NULL,
  email          TEXT UNIQUE NOT NULL,
  password_hash  TEXT NOT NULL,
  role           TEXT NOT NULL DEFAULT 'customer'
                  CHECK (role IN ('customer','seller','admin')),
  twofa_enabled  INTEGER NOT NULL DEFAULT 0,
  twofa_secret   TEXT,
  last_login     TIMESTAMP,
  locked_until   INTEGER
);

CREATE TABLE IF NOT EXISTS users_admin    (user_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users_seller   (user_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users_customer (user_id INTEGER PRIMARY KEY);

CREATE INDEX IF NOT EXISTS idx_users_role       ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);


-- Catalog

CREATE TABLE IF NOT EXISTS products (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  description TEXT NOT NULL,
  price       REAL NOT NULL,
  stock       INTEGER NOT NULL,
  seller_id   INTEGER,
  image       TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_products_created_at ON products(created_at);
CREATE INDEX IF NOT EXISTS idx_products_price      ON products(price);
CREATE INDEX IF NOT EXISTS idx_products_seller     ON products(seller_id);


-- Reviews

CREATE TABLE IF NOT EXISTS reviews (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id   INTEGER NOT NULL,
  user_id      INTEGER NOT NULL,
  rating       INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  content      TEXT,
  image        TEXT,
  content_html TEXT,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reviews_product_created
  ON reviews(product_id, created_at);


-- Orders

CREATE TABLE IF NOT EXISTS orders (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id   INTEGER NOT NULL,
  buyer_id     INTEGER NOT NULL,
  quantity     INTEGER NOT NULL CHECK (quantity >= 1),
  total_price  REAL NOT NULL,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
  FOREIGN KEY (buyer_id)   REFERENCES users(id)    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);
CREATE INDEX IF NOT EXISTS idx_orders_buyer      ON orders(buyer_id);


-- Audit Events

CREATE TABLE IF NOT EXISTS audit_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  event_type  TEXT NOT NULL,
  user_id     INTEGER,
  route       TEXT,
  method      TEXT,
  product_id  INTEGER,
  ms          INTEGER,
  ip          TEXT,
  ua          TEXT,
  session_id  TEXT,
  meta        TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_type_ip_ts
  ON audit_events(event_type, ip, ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_session_event_ts
  ON audit_events(session_id, event_type, ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_ts
  ON audit_events(user_id, ts);

-- ==========================================
-- Suspicious Activities + Triggers + Views
-- ==========================================
CREATE TABLE IF NOT EXISTS suspicious_activities (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  severity   TEXT NOT NULL DEFAULT 'low'
               CHECK (severity IN ('low','medium','high','critical')),
  category   TEXT NOT NULL,
  reason     TEXT,
  score      INTEGER NOT NULL DEFAULT 0
               CHECK (score >= 0 AND score <= 100),
  event_id   INTEGER,
  user_id    INTEGER,
  ip         TEXT,
  ua         TEXT,
  session_id TEXT,
  route      TEXT,
  method     TEXT,
  meta       TEXT,
  FOREIGN KEY(event_id) REFERENCES audit_events(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sa_ts       ON suspicious_activities(ts);
CREATE INDEX IF NOT EXISTS idx_sa_ip       ON suspicious_activities(ip);
CREATE INDEX IF NOT EXISTS idx_sa_user     ON suspicious_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_sa_category ON suspicious_activities(category);
CREATE INDEX IF NOT EXISTS idx_sa_severity ON suspicious_activities(severity);

-- Prevent duplicate linking to the same audit event
CREATE UNIQUE INDEX IF NOT EXISTS ux_sa_event
  ON suspicious_activities(event_id)
  WHERE event_id IS NOT NULL;

-- Triggers

-- (1) Bruteforce: >=5 login failures from same IP in 10 minutes Security function
CREATE TRIGGER IF NOT EXISTS tr_sa_bruteforce
AFTER INSERT ON audit_events
WHEN NEW.event_type = 'login_failure'
  AND (
    SELECT COUNT(*)
    FROM audit_events
    WHERE event_type = 'login_failure'
      AND ip = NEW.ip
      AND ts >= datetime('now','-10 minutes')
  ) >= 5
BEGIN
  INSERT OR IGNORE INTO suspicious_activities
    (ts,severity,category,reason,score,event_id,user_id,ip,ua,session_id,route,method,meta)
  VALUES
    (CURRENT_TIMESTAMP,'high','bruteforce',
     '>=5 login failures from same IP in 10 minutes',80,
     NEW.id,NEW.user_id,NEW.ip,NEW.ua,NEW.session_id,NEW.route,NEW.method,NEW.meta);
END;

-- (2) App signalled suspicious activity
CREATE TRIGGER IF NOT EXISTS tr_sa_app_signal
AFTER INSERT ON audit_events
WHEN NEW.event_type = 'suspicious_activity'
BEGIN
  INSERT OR IGNORE INTO suspicious_activities
    (ts,severity,category,reason,score,event_id,user_id,ip,ua,session_id,route,method,meta)
  VALUES
    (CURRENT_TIMESTAMP,'medium','suspicious_activity',
     'App signalled suspicious activity',60,
     NEW.id,NEW.user_id,NEW.ip,NEW.ua,NEW.session_id,NEW.route,NEW.method,NEW.meta);
END;

-- (3) Rate limited requests
CREATE TRIGGER IF NOT EXISTS tr_sa_rate_limit
AFTER INSERT ON audit_events
WHEN NEW.event_type = 'rate_limited'
BEGIN
  INSERT OR IGNORE INTO suspicious_activities
    (ts,severity,category,reason,score,event_id,user_id,ip,ua,session_id,route,method,meta)
  VALUES
    (CURRENT_TIMESTAMP,'low','rate_limit',
     'Client hit rate limiter',30,
     NEW.id,NEW.user_id,NEW.ip,NEW.ua,NEW.session_id,NEW.route,NEW.method,NEW.meta);
END;

-- (4) Unauthenticated POST to /admin/ 
CREATE TRIGGER IF NOT EXISTS tr_sa_admin_unauth
AFTER INSERT ON audit_events
WHEN NEW.method = 'POST'
  AND NEW.route LIKE '/admin%'
  AND NEW.user_id IS NULL
BEGIN
  INSERT OR IGNORE INTO suspicious_activities
    (ts,severity,category,reason,score,event_id,user_id,ip,ua,session_id,route,method,meta)
  VALUES
    (CURRENT_TIMESTAMP,'critical','admin_unauth',
     'Unauthenticated POST to admin route',90,
     NEW.id,NEW.user_id,NEW.ip,NEW.ua,NEW.session_id,NEW.route,NEW.method,NEW.meta);
END;

-- (5) Cart abuse: >20 cart mutations per minute per session
CREATE TRIGGER IF NOT EXISTS tr_sa_cart_abuse
AFTER INSERT ON audit_events
WHEN NEW.event_type IN ('add_to_cart','cart_update','cart_remove')
  AND (
    SELECT COUNT(*)
    FROM audit_events
    WHERE event_type IN ('add_to_cart','cart_update','cart_remove')
      AND session_id = NEW.session_id
      AND ts >= datetime('now','-1 minute')
  ) > 20
BEGIN
  INSERT OR IGNORE INTO suspicious_activities
    (ts,severity,category,reason,score,event_id,user_id,ip,ua,session_id,route,method,meta)
  VALUES
    (CURRENT_TIMESTAMP,'medium','cart_abuse',
     'High-frequency cart mutations by same session in 1 minute',55,
     NEW.id,NEW.user_id,NEW.ip,NEW.ua,NEW.session_id,NEW.route,NEW.method,NEW.meta);
END;

-- Analytics views
CREATE VIEW IF NOT EXISTS suspicious_recent AS
SELECT DATE(ts) AS day, category, COUNT(*) AS events
FROM suspicious_activities
WHERE ts >= datetime('now','-30 days')
GROUP BY DATE(ts), category
ORDER BY day DESC, category;

CREATE VIEW IF NOT EXISTS suspicious_by_ip AS
SELECT ip, COUNT(*) AS events, MAX(ts) AS last_seen
FROM suspicious_activities
GROUP BY ip
ORDER BY events DESC, last_seen DESC;

CREATE VIEW IF NOT EXISTS suspicious_by_user AS
SELECT user_id, COUNT(*) AS events, MAX(ts) AS last_seen
FROM suspicious_activities
WHERE user_id IS NOT NULL
GROUP BY user_id
ORDER BY events DESC, last_seen DESC;

CREATE VIEW IF NOT EXISTS suspicious_hourly AS
SELECT strftime('%H', ts) AS hour_24, category, COUNT(*) AS events
FROM suspicious_activities
GROUP BY hour_24, category
ORDER BY hour_24, category;
