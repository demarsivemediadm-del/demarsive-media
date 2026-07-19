const express = require('express');
const multer  = require('multer');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'demarsive-secret-key-2025';
const DB_PATH = path.join(__dirname, 'data', 'db.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random()*1e9) + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 10*1024*1024 }, fileFilter: (req,file,cb) => cb(null, /jpeg|jpg|png|gif|webp/.test(file.mimetype)) });

function readDB(){ return JSON.parse(fs.readFileSync(DB_PATH,'utf8')) }
function writeDB(data){ fs.writeFileSync(DB_PATH, JSON.stringify(data,null,2)) }

function auth(req,res,next){
  const token = req.headers.authorization?.split(' ')[1];
  if(!token) return res.status(401).json({error:'No token'});
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch{ res.status(401).json({error:'Invalid token'}) }
}

// Public
app.get('/api/site', (req,res) => {
  const db = readDB();
  res.json({ site: db.site, portfolio: db.portfolio, blog: db.blog.filter(p=>p.published) });
});

// Auth
app.post('/api/auth/login', async (req,res) => {
  const {email,password} = req.body;
  const db = readDB();
  if(email !== db.admin.email) return res.status(401).json({error:'Invalid credentials'});
  if(!await bcrypt.compare(password, db.admin.password)) return res.status(401).json({error:'Invalid credentials'});
  res.json({ token: jwt.sign({email}, JWT_SECRET, {expiresIn:'7d'}), email });
});

app.post('/api/auth/change-password', auth, async (req,res) => {
  const {currentPassword, newPassword} = req.body;
  const db = readDB();
  if(!await bcrypt.compare(currentPassword, db.admin.password)) return res.status(401).json({error:'Wrong password'});
  db.admin.password = await bcrypt.hash(newPassword, 10);
  writeDB(db);
  res.json({success:true});
});

// Site text
app.put('/api/site', auth, (req,res) => {
  const db = readDB();
  db.site = {...db.site, ...req.body};
  writeDB(db);
  res.json({success:true, site:db.site});
});

// Portfolio
app.get('/api/portfolio', (req,res) => res.json(readDB().portfolio));

app.post('/api/portfolio', auth, upload.single('image'), (req,res) => {
  const db = readDB();
  const item = {
    id: 'p'+Date.now(),
    category: req.body.category||'graphic',
    title: req.body.title||'New Project',
    description: req.body.description||'',
    tags: req.body.tags ? JSON.parse(req.body.tags) : [],
    image: req.file ? '/uploads/'+req.file.filename : '',
    emoji: req.body.emoji||'🎨',
    featured: req.body.featured==='true'
  };
  db.portfolio.push(item);
  writeDB(db);
  res.json({success:true, item});
});

app.put('/api/portfolio/:id', auth, upload.single('image'), (req,res) => {
  const db = readDB();
  const idx = db.portfolio.findIndex(p=>p.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Not found'});
  db.portfolio[idx] = {
    ...db.portfolio[idx],
    category: req.body.category||db.portfolio[idx].category,
    title: req.body.title||db.portfolio[idx].title,
    description: req.body.description||db.portfolio[idx].description,
    tags: req.body.tags ? JSON.parse(req.body.tags) : db.portfolio[idx].tags,
    emoji: req.body.emoji||db.portfolio[idx].emoji,
    featured: req.body.featured!==undefined ? req.body.featured==='true' : db.portfolio[idx].featured,
    image: req.file ? '/uploads/'+req.file.filename : db.portfolio[idx].image
  };
  writeDB(db);
  res.json({success:true, item:db.portfolio[idx]});
});

app.delete('/api/portfolio/:id', auth, (req,res) => {
  const db = readDB();
  db.portfolio = db.portfolio.filter(p=>p.id!==req.params.id);
  writeDB(db);
  res.json({success:true});
});

// Blog
app.get('/api/blog', (req,res) => {
  const db = readDB();
  res.json(req.headers.authorization ? db.blog : db.blog.filter(b=>b.published));
});

app.post('/api/blog', auth, upload.single('image'), (req,res) => {
  const db = readDB();
  const post = {
    id: 'b'+Date.now(),
    title: req.body.title||'New Post',
    date: req.body.date||new Date().toISOString().split('T')[0],
    category: req.body.category||'news',
    excerpt: req.body.excerpt||'',
    content: req.body.content||'',
    image: req.file ? '/uploads/'+req.file.filename : '',
    emoji: req.body.emoji||'📝',
    published: req.body.published==='true'
  };
  db.blog.unshift(post);
  writeDB(db);
  res.json({success:true, post});
});

app.put('/api/blog/:id', auth, upload.single('image'), (req,res) => {
  const db = readDB();
  const idx = db.blog.findIndex(b=>b.id===req.params.id);
  if(idx===-1) return res.status(404).json({error:'Not found'});
  db.blog[idx] = {
    ...db.blog[idx],
    title: req.body.title||db.blog[idx].title,
    date: req.body.date||db.blog[idx].date,
    category: req.body.category||db.blog[idx].category,
    excerpt: req.body.excerpt||db.blog[idx].excerpt,
    content: req.body.content||db.blog[idx].content,
    emoji: req.body.emoji||db.blog[idx].emoji,
    published: req.body.published!==undefined ? req.body.published==='true' : db.blog[idx].published,
    image: req.file ? '/uploads/'+req.file.filename : db.blog[idx].image
  };
  writeDB(db);
  res.json({success:true, post:db.blog[idx]});
});

app.delete('/api/blog/:id', auth, (req,res) => {
  const db = readDB();
  db.blog = db.blog.filter(b=>b.id!==req.params.id);
  writeDB(db);
  res.json({success:true});
});

// Upload
app.post('/api/upload', auth, upload.single('image'), (req,res) => {
  if(!req.file) return res.status(400).json({error:'No file'});
  res.json({success:true, url:'/uploads/'+req.file.filename});
});

app.get('/', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/admin', (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/admin/', (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));

app.listen(PORT, () => {
  console.log(`\n✅ Demarsive Media CMS running!`);
  console.log(`   Site:  http://localhost:${PORT}`);
  console.log(`   Admin: http://localhost:${PORT}/admin`);
  console.log(`   Login: admin@demarsivemedia.com / password\n`);
});
