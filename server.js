const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const COMMISSION_RATE = 0.05;
const ROOT = __dirname;
const UPLOADS = path.join(ROOT, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new DatabaseSync(path.join(ROOT, 'data.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pass TEXT, role TEXT, country TEXT, company TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, supplier_id INTEGER, name TEXT, category TEXT, description TEXT, price REAL, unit TEXT, stock INTEGER, country TEXT, image TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, buyer_id INTEGER, supplier_id INTEGER, subtotal REAL, commission REAL, supplier_payout REAL, payment_method TEXT, card_brand TEXT, card_last4 TEXT, payment_status TEXT, status TEXT, address TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id INTEGER, product_id INTEGER, name TEXT, price REAL, qty INTEGER);
CREATE TABLE IF NOT EXISTS properties(id INTEGER PRIMARY KEY, seller_id INTEGER, type TEXT, title TEXT, description TEXT, price REAL, country TEXT, city TEXT, address TEXT, bedrooms INTEGER, bathrooms INTEGER, area REAL, area_unit TEXT, year_built INTEGER, features TEXT, zoning TEXT, title_deed TEXT, utilities TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS property_media(id INTEGER PRIMARY KEY, property_id INTEGER, url TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS product_media(id INTEGER PRIMARY KEY, product_id INTEGER, url TEXT, kind TEXT);
`);

// Seed admin from .env (git-ignored) or environment variables
try {
  for (const line of fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
} catch {}
const adminEmail = (process.env.ADMIN_EMAIL || 'admin').toLowerCase();
const adminPass = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString('hex');
if (!db.prepare('SELECT 1 FROM users WHERE email=?').get(adminEmail)) {
  const old = db.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").get();
  if (old) db.prepare('UPDATE users SET email=?,pass=?,name=? WHERE id=?').run(adminEmail, hash(adminPass), 'Oman Admin', old.id);
  else db.prepare('INSERT INTO users(name,email,pass,role,country,company) VALUES(?,?,?,?,?,?)')
    .run('Oman Admin', adminEmail, hash(adminPass), 'admin', 'US', 'BuildChain');
  console.log(`Admin account ready: ${adminEmail}${process.env.ADMIN_PASSWORD ? '' : ' / ' + adminPass}`);
}

function hash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verify(pw, stored) {
  const [salt, h] = stored.split(':');
  const a = Buffer.from(h, 'hex'), b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const round = n => Math.round(n * 100) / 100;

function luhn(num) {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let d = +num[i];
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}
function cardBrand(n) {
  if (/^4\d{12}(\d{3})?(\d{3})?$/.test(n)) return 'visa';
  if (/^(5[1-5]\d{14}|2(2[2-9]\d|[3-6]\d\d|7[01]\d|720)\d{12})$/.test(n)) return 'mastercard';
  if (/^(6011\d{12}|65\d{14}|64[4-9]\d{13}|622\d{13})$/.test(n)) return 'discover';
  return null;
}

/*
 * Payment gateway adapter. Replace the body with a real PSP call (e.g. Stripe
 * Connect / Adyen for Platforms) using tokenised card data. Raw card numbers
 * must never reach your server in production (PCI-DSS); this demo validates
 * and discards them, keeping only brand + last4.
 */
function authorizeCard(card, amount) {
  const num = String(card.number || '').replace(/\D/g, '');
  const brand = cardBrand(num);
  if (!brand || !luhn(num)) throw new Error('Only valid Visa, Mastercard or Discover cards are accepted');
  const m = +card.exp_month, y = +card.exp_year;
  const now = new Date();
  if (!(m >= 1 && m <= 12) || (y < now.getFullYear() % 100 + 2000 && y > 99) || new Date(y < 100 ? 2000 + y : y, m, 1) <= now)
    throw new Error('Card expired or invalid expiry');
  if (!/^\d{3,4}$/.test(String(card.cvc || ''))) throw new Error('Invalid CVC');
  return { brand, last4: num.slice(-4), amount };
}

const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime' };
const MEDIA = {
  'image/png': ['.png', 'image', 10e6], 'image/jpeg': ['.jpg', 'image', 10e6], 'image/webp': ['.webp', 'image', 10e6],
  'video/mp4': ['.mp4', 'video', 200e6], 'video/webm': ['.webm', 'video', 200e6], 'video/quicktime': ['.mov', 'video', 200e6],
};
// Streams a raw file body to disk so large videos never sit in memory.
function receiveFile(req) {
  return new Promise((resolve, reject) => {
    const spec = MEDIA[(req.headers['content-type'] || '').split(';')[0]];
    if (!spec) return reject(new Error('Unsupported file type. Use PNG, JPG, WEBP, MP4, WEBM or MOV'));
    const name = crypto.randomBytes(12).toString('hex') + spec[0];
    const file = path.join(UPLOADS, name);
    const out = fs.createWriteStream(file);
    let size = 0, failed = false;
    const fail = e => { if (failed) return; failed = true; out.destroy(); fs.unlink(file, () => {}); reject(e); };
    req.on('data', c => {
      size += c.length;
      if (size > spec[2]) { fail(new Error(`File too large (max ${spec[2] / 1e6}MB for ${spec[1]}s)`)); req.unpipe(out); req.resume(); }
    });
    req.on('error', fail);
    out.on('error', fail);
    out.on('finish', () => { if (!failed) resolve({ url: '/uploads/' + name, kind: spec[1] }); });
    req.pipe(out);
  });
}
const num = v => (v === '' || v == null || isNaN(+v)) ? null : +v;

function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}
function body(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > 8e6) { reject(new Error('Payload too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks)) : {}); } catch { reject(new Error('Bad JSON')); } });
  });
}
function user(req) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  if (!t) return null;
  return db.prepare('SELECT u.id,u.name,u.email,u.role,u.country,u.company FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(t) || null;
}
function saveImage(dataUrl) {
  const m = /^data:image\/(png|jpeg|webp|gif);base64,(.+)$/.exec(dataUrl || '');
  if (!m) return null;
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 5e6) throw new Error('Image too large (max 5MB)');
  const name = crypto.randomBytes(12).toString('hex') + '.' + (m[1] === 'jpeg' ? 'jpg' : m[1]);
  fs.writeFileSync(path.join(UPLOADS, name), buf);
  return '/uploads/' + name;
}

const routes = {
  'POST /api/signup': async (req, res) => {
    const b = await body(req);
    if (!b.name || !b.email || !b.password || b.password.length < 8) throw new Error('Name, email and a password of 8+ characters required');
    if (!['buyer', 'supplier'].includes(b.role)) throw new Error('Invalid role');
    if (!b.country) throw new Error('Country required');
    try {
      const r = db.prepare('INSERT INTO users(name,email,pass,role,country,company) VALUES(?,?,?,?,?,?)')
        .run(b.name, b.email.toLowerCase(), hash(b.password), b.role, b.country, b.company || '');
      return login(res, r.lastInsertRowid);
    } catch { throw new Error('Email already registered'); }
  },
  'POST /api/login': async (req, res) => {
    const b = await body(req);
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(b.email || '').toLowerCase());
    if (!u || !verify(String(b.password || ''), u.pass)) return send(res, 401, { error: 'Invalid credentials' });
    login(res, u.id);
  },
  'GET /api/me': async (req, res) => send(res, 200, { user: user(req) }),
  'GET /api/products': async (req, res, url) => {
    const q = url.searchParams;
    let sql = 'SELECT p.*,u.company supplier FROM products p JOIN users u ON u.id=p.supplier_id WHERE p.stock>0';
    const args = [];
    if (q.get('country')) { sql += ' AND p.country=?'; args.push(q.get('country')); }
    if (q.get('category')) { sql += ' AND p.category=?'; args.push(q.get('category')); }
    if (q.get('q')) { sql += ' AND (p.name LIKE ? OR p.description LIKE ?)'; args.push(`%${q.get('q')}%`, `%${q.get('q')}%`); }
    send(res, 200, prodMedia(db.prepare(sql + ' ORDER BY p.id DESC LIMIT 200').all(...args)));
  },
  'GET /api/my-products': async (req, res) => {
    const u = need(req);
    if (u.role === 'buyer') throw Object.assign(new Error('Forbidden'), { code: 403 });
    send(res, 200, prodMedia(u.role === 'admin'
      ? db.prepare('SELECT p.*,us.company supplier FROM products p JOIN users us ON us.id=p.supplier_id ORDER BY p.id DESC').all()
      : db.prepare('SELECT * FROM products WHERE supplier_id=? ORDER BY id DESC').all(u.id)));
  },
  'POST /api/products/update': async (req, res) => {
    const u = need(req);
    const b = await body(req);
    const p = db.prepare('SELECT * FROM products WHERE id=?').get(+b.id);
    if (!p) throw new Error('Product not found');
    if (u.role !== 'admin' && p.supplier_id !== u.id) throw Object.assign(new Error('Forbidden'), { code: 403 });
    const price = +b.price, stock = parseInt(b.stock, 10);
    if (!b.name || !(price > 0) || !(stock >= 0) || !b.category) throw new Error('Name, category, positive price and stock required');
    db.exec('BEGIN');
    try {
      db.prepare('UPDATE products SET name=?,category=?,description=?,price=?,unit=?,stock=?,country=? WHERE id=?')
        .run(b.name, b.category, b.description || '', round(price), b.unit || 'unit', stock, b.country || p.country, p.id);
      if (p.image && !db.prepare('SELECT 1 FROM product_media WHERE product_id=?').get(p.id))
        db.prepare("INSERT INTO product_media(product_id,url,kind) VALUES(?,?,'image')").run(p.id, p.image);
      syncMedia('product_media', 'product_id', p.id, b);
      const first = db.prepare("SELECT url FROM product_media WHERE product_id=? AND kind='image' ORDER BY id LIMIT 1").get(p.id);
      db.prepare('UPDATE products SET image=? WHERE id=?').run(first ? first.url : null, p.id);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    send(res, 200, { ok: true });
  },
  'POST /api/products/delete': async (req, res) => {
    const u = need(req);
    const b = await body(req);
    const p = db.prepare('SELECT * FROM products WHERE id=?').get(+b.id);
    if (!p) throw new Error('Product not found');
    if (u.role !== 'admin' && p.supplier_id !== u.id) throw Object.assign(new Error('Forbidden'), { code: 403 });
    for (const m of db.prepare('SELECT url FROM product_media WHERE product_id=?').all(p.id)) unlinkUpload(m.url);
    db.prepare('DELETE FROM product_media WHERE product_id=?').run(p.id);
    db.prepare('DELETE FROM products WHERE id=?').run(p.id);
    send(res, 200, { ok: true });
  },
  'POST /api/products': async (req, res) => {
    const u = need(req, 'supplier');
    const b = await body(req);
    const price = +b.price, stock = parseInt(b.stock, 10);
    if (!b.name || !(price > 0) || !(stock >= 0) || !b.category) throw new Error('Name, category, positive price and stock required');
    const media = (Array.isArray(b.media) ? b.media : []).filter(m => /^\/uploads\/[a-f0-9]+\.(png|jpg|webp|mp4|webm|mov)$/.test(m.url || ''));
    const image = media.find(m => !/\.(mp4|webm|mov)$/.test(m.url));
    const r = db.prepare('INSERT INTO products(supplier_id,name,category,description,price,unit,stock,country,image) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(u.id, b.name, b.category, b.description || '', round(price), b.unit || 'unit', stock, b.country || u.country, image ? image.url : null);
    for (const m of media) db.prepare('INSERT INTO product_media(product_id,url,kind) VALUES(?,?,?)').run(r.lastInsertRowid, m.url, /\.(mp4|webm|mov)$/.test(m.url) ? 'video' : 'image');
    send(res, 201, { id: r.lastInsertRowid });
  },
  'POST /api/orders': async (req, res) => {
    const u = need(req, 'buyer');
    const b = await body(req);
    if (!b.address) throw new Error('Delivery address required');
    if (!['cod', 'card'].includes(b.payment_method)) throw new Error('Invalid payment method');
    if (!Array.isArray(b.items) || !b.items.length) throw new Error('Cart is empty');
    const bySupplier = {};
    for (const it of b.items) {
      const p = db.prepare('SELECT * FROM products WHERE id=?').get(+it.id);
      const qty = parseInt(it.qty, 10);
      if (!p || !(qty > 0)) throw new Error('Invalid item');
      if (p.stock < qty) throw new Error(`Insufficient stock for ${p.name}`);
      (bySupplier[p.supplier_id] ||= []).push({ p, qty });
    }
    const total = round(Object.values(bySupplier).flat().reduce((s, { p, qty }) => s + p.price * qty, 0));
    let card = null;
    if (b.payment_method === 'card') card = authorizeCard(b.card || {}, total);
    const ids = [];
    db.exec('BEGIN');
    try {
      for (const [sid, lines] of Object.entries(bySupplier)) {
        const subtotal = round(lines.reduce((s, { p, qty }) => s + p.price * qty, 0));
        const commission = round(subtotal * COMMISSION_RATE);
        const r = db.prepare('INSERT INTO orders(buyer_id,supplier_id,subtotal,commission,supplier_payout,payment_method,card_brand,card_last4,payment_status,status,address) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
          .run(u.id, +sid, subtotal, commission, round(subtotal - commission), b.payment_method,
            card && card.brand, card && card.last4, card ? 'held_in_escrow' : 'due_on_delivery', 'pending', b.address);
        for (const { p, qty } of lines) {
          db.prepare('INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES(?,?,?,?,?)').run(r.lastInsertRowid, p.id, p.name, p.price, qty);
          db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(qty, p.id);
        }
        ids.push(r.lastInsertRowid);
      }
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    send(res, 201, { orders: ids, total });
  },
  'GET /api/orders': async (req, res) => {
    const u = need(req);
    const col = u.role === 'buyer' ? 'buyer_id' : u.role === 'supplier' ? 'supplier_id' : null;
    const orders = col ? db.prepare(`SELECT * FROM orders WHERE ${col}=? ORDER BY id DESC`).all(u.id)
      : db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
    for (const o of orders) o.items = db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id);
    send(res, 200, orders);
  },
  'POST /api/orders/status': async (req, res) => {
    const u = need(req, 'supplier');
    const b = await body(req);
    const o = db.prepare('SELECT * FROM orders WHERE id=? AND supplier_id=?').get(+b.id, u.id);
    if (!o) throw new Error('Order not found');
    const next = { pending: 'shipped', shipped: 'delivered' }[o.status];
    if (next !== b.status) throw new Error('Invalid status transition');
    // Escrowed card funds release (minus 5%) on delivery; COD commission is invoiced to supplier.
    const pay = b.status !== 'delivered' ? o.payment_status
      : o.payment_method === 'card' ? 'paid_out' : 'cash_collected_commission_owed';
    db.prepare('UPDATE orders SET status=?,payment_status=? WHERE id=?').run(b.status, pay, o.id);
    send(res, 200, { ok: true });
  },
  'POST /api/upload': async (req, res) => {
    const u = need(req);
    if (!['supplier', 'admin'].includes(u.role)) throw Object.assign(new Error('Forbidden'), { code: 403 });
    send(res, 201, await receiveFile(req));
  },
  'GET /api/properties': async (req, res, url) => {
    const q = url.searchParams;
    let sql = 'SELECT p.*,u.company seller FROM properties p JOIN users u ON u.id=p.seller_id WHERE 1=1';
    const args = [];
    for (const f of ['type', 'country']) if (q.get(f)) { sql += ` AND p.${f}=?`; args.push(q.get(f)); }
    if (q.get('city')) { sql += ' AND p.city LIKE ?'; args.push(`%${q.get('city')}%`); }
    if (num(q.get('max_price'))) { sql += ' AND p.price<=?'; args.push(+q.get('max_price')); }
    if (num(q.get('min_bedrooms'))) { sql += ' AND p.bedrooms>=?'; args.push(+q.get('min_bedrooms')); }
    send(res, 200, withMedia(db.prepare(sql + ' ORDER BY p.id DESC LIMIT 100').all(...args)));
  },
  'GET /api/my-properties': async (req, res) => {
    const u = need(req);
    if (u.role === 'buyer') throw Object.assign(new Error('Forbidden'), { code: 403 });
    send(res, 200, withMedia(u.role === 'admin'
      ? db.prepare('SELECT p.*,us.company seller FROM properties p JOIN users us ON us.id=p.seller_id ORDER BY p.id DESC').all()
      : db.prepare('SELECT * FROM properties WHERE seller_id=? ORDER BY id DESC').all(u.id)));
  },
  'POST /api/properties/update': async (req, res) => {
    const u = need(req);
    const b = await body(req);
    const p = db.prepare('SELECT * FROM properties WHERE id=?').get(+b.id);
    if (!p) throw new Error('Listing not found');
    if (u.role !== 'admin' && p.seller_id !== u.id) throw Object.assign(new Error('Forbidden'), { code: 403 });
    if (!['house', 'land'].includes(b.type)) throw new Error('Choose house or land');
    const price = +b.price;
    if (!b.title || !(price > 0) || !b.country || !b.city) throw new Error('Title, country, city and a positive price are required');
    if (!(num(b.area) > 0)) throw new Error('Size/area is required');
    db.exec('BEGIN');
    try {
      db.prepare('UPDATE properties SET type=?,title=?,description=?,price=?,country=?,city=?,address=?,bedrooms=?,bathrooms=?,area=?,area_unit=?,year_built=?,features=?,zoning=?,title_deed=?,utilities=? WHERE id=?')
        .run(b.type, b.title, b.description || '', round(price), b.country, b.city, b.address || '', num(b.bedrooms), num(b.bathrooms), num(b.area),
          ['acres', 'hectares', 'sqft'].includes(b.area_unit) ? b.area_unit : 'sqm', num(b.year_built), b.features || '', b.zoning || '', b.title_deed || '', b.utilities || '', p.id);
      syncMedia('property_media', 'property_id', p.id, b);
      if (!db.prepare('SELECT 1 FROM property_media WHERE property_id=?').get(p.id)) throw new Error('A listing needs at least one photo or video');
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    send(res, 200, { ok: true });
  },
  'POST /api/properties/delete': async (req, res) => {
    const u = need(req);
    const b = await body(req);
    const p = db.prepare('SELECT * FROM properties WHERE id=?').get(+b.id);
    if (!p) throw new Error('Listing not found');
    if (u.role !== 'admin' && p.seller_id !== u.id) throw Object.assign(new Error('Forbidden'), { code: 403 });
    for (const m of db.prepare('SELECT url FROM property_media WHERE property_id=?').all(p.id)) unlinkUpload(m.url);
    db.prepare('DELETE FROM property_media WHERE property_id=?').run(p.id);
    db.prepare('DELETE FROM properties WHERE id=?').run(p.id);
    send(res, 200, { ok: true });
  },
  'GET /api/properties/contact': async (req, res, url) => {
    need(req);
    const r = db.prepare('SELECT u.name,u.email,u.company FROM properties p JOIN users u ON u.id=p.seller_id WHERE p.id=?').get(+url.searchParams.get('id'));
    if (!r) throw new Error('Listing not found');
    send(res, 200, r);
  },
  'POST /api/properties': async (req, res) => {
    const u = need(req, 'supplier');
    const b = await body(req);
    if (!['house', 'land'].includes(b.type)) throw new Error('Choose house or land');
    const price = +b.price;
    if (!b.title || !(price > 0) || !b.country || !b.city) throw new Error('Title, country, city and a positive price are required');
    if (!(num(b.area) > 0)) throw new Error('Size/area is required');
    const media = (Array.isArray(b.media) ? b.media : []).filter(m => /^\/uploads\/[a-f0-9]+\.(png|jpg|webp|mp4|webm|mov)$/.test(m.url || ''));
    if (!media.length) throw new Error('Upload at least one photo or video');
    const r = db.prepare('INSERT INTO properties(seller_id,type,title,description,price,country,city,address,bedrooms,bathrooms,area,area_unit,year_built,features,zoning,title_deed,utilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(u.id, b.type, b.title, b.description || '', round(price), b.country, b.city, b.address || '',
        num(b.bedrooms), num(b.bathrooms), num(b.area), b.area_unit === 'acres' || b.area_unit === 'hectares' || b.area_unit === 'sqft' ? b.area_unit : 'sqm',
        num(b.year_built), b.features || '', b.zoning || '', b.title_deed || '', b.utilities || '');
    for (const m of media) db.prepare('INSERT INTO property_media(property_id,url,kind) VALUES(?,?,?)').run(r.lastInsertRowid, m.url, /\.(mp4|webm|mov)$/.test(m.url) ? 'video' : 'image');
    send(res, 201, { id: r.lastInsertRowid });
  },
  'GET /api/admin/summary': async (req, res) => {
    need(req, 'admin');
    send(res, 200, db.prepare(`SELECT COUNT(*) orders, COALESCE(SUM(subtotal),0) gmv,
      COALESCE(SUM(CASE WHEN status='delivered' THEN commission END),0) earned_commission,
      COALESCE(SUM(CASE WHEN status!='delivered' THEN commission END),0) pending_commission FROM orders`).get());
  },
};

const MEDIA_URL = /^\/uploads\/[a-f0-9]+\.(png|jpg|webp|mp4|webm|mov)$/;
const unlinkUpload = url => { if (MEDIA_URL.test(url || '')) fs.unlink(path.join(UPLOADS, path.basename(url)), () => {}); };
// Removes media listed in b.remove_media and attaches newly uploaded b.media.
function syncMedia(table, col, id, b) {
  for (const url of Array.isArray(b.remove_media) ? b.remove_media : []) {
    if (db.prepare(`SELECT 1 FROM ${table} WHERE ${col}=? AND url=?`).get(id, url)) {
      db.prepare(`DELETE FROM ${table} WHERE ${col}=? AND url=?`).run(id, url);
      unlinkUpload(url);
    }
  }
  for (const m of Array.isArray(b.media) ? b.media : []) {
    if (!MEDIA_URL.test(m.url || '')) continue;
    db.prepare(`INSERT INTO ${table}(${col},url,kind) VALUES(?,?,?)`).run(id, m.url, /\.(mp4|webm|mov)$/.test(m.url) ? 'video' : 'image');
  }
}
function prodMedia(rows) {
  for (const r of rows) {
    r.media = db.prepare('SELECT url,kind FROM product_media WHERE product_id=? ORDER BY id').all(r.id);
    if (!r.media.length && r.image) r.media = [{ url: r.image, kind: 'image' }];
  }
  return rows;
}
function withMedia(rows) {
  for (const r of rows) r.media = db.prepare('SELECT url,kind FROM property_media WHERE property_id=? ORDER BY id').all(r.id);
  return rows;
}
function login(res, id) {
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?)').run(token, id);
  const u = db.prepare('SELECT id,name,email,role,country,company FROM users WHERE id=?').get(id);
  send(res, 200, { token, user: u });
}
function need(req, role) {
  const u = user(req);
  if (!u) throw Object.assign(new Error('Login required'), { code: 401 });
  if (role && u.role !== role) throw Object.assign(new Error('Forbidden'), { code: 403 });
  return u;
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const key = `${req.method} ${url.pathname}`;
  try {
    if (routes[key]) return await routes[key](req, res, url);
    if (req.method !== 'GET') return send(res, 404, { error: 'Not found' });
    let file;
    if (url.pathname.startsWith('/uploads/')) file = path.join(UPLOADS, path.basename(url.pathname));
    else file = path.join(ROOT, 'public', url.pathname === '/' ? 'index.html' : path.normalize(url.pathname).replace(/^(\.\.[\\/])+/, ''));
    if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, { error: 'Not found' });
    const headers = { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Accept-Ranges': 'bytes' };
    if (file.endsWith('.html')) headers['Cache-Control'] = 'no-store';
    const total = fs.statSync(file).size;
    const rg = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (rg && (rg[1] || rg[2])) {
      let start = rg[1] ? +rg[1] : Math.max(0, total - +rg[2]);
      let end = rg[1] && rg[2] ? Math.min(+rg[2], total - 1) : total - 1;
      if (start > end || start >= total) { res.writeHead(416, { 'Content-Range': `bytes */${total}` }); return res.end(); }
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${total}`, 'Content-Length': end - start + 1 });
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    res.writeHead(200, { ...headers, 'Content-Length': total });
    fs.createReadStream(file).pipe(res);
  } catch (e) {
    send(res, e.code || 400, { error: e.message });
  }
}).listen(PORT, () => console.log(`BuildChain running at http://localhost:${PORT}`));
