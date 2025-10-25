const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const loki = require('lokijs');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({ dest: UPLOAD_DIR });

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use('/static', express.static(path.join(__dirname, 'public')));

// Use LokiJS (pure JS DB) to avoid native build steps on Windows for prototypes
const dbFile = path.join(__dirname, 'klh.json');
const db = new loki(dbFile, {
  autoload: true,
  autoloadCallback: databaseInitialize,
  autosave: true,
  autosaveInterval: 10000
});

function databaseInitialize() {
  let users = db.getCollection('users');
  if (!users) users = db.addCollection('users', { unique: ['email'] });

  let videos = db.getCollection('videos');
  if (!videos) videos = db.addCollection('videos');

  let playlists = db.getCollection('playlists');
  if (!playlists) playlists = db.addCollection('playlists');

  let comments = db.getCollection('comments');
  if (!comments) comments = db.addCollection('comments');
}

function saveDb() { db.saveDatabase(); }

// Helpers
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.redirect('/login');
  }
}

// Routes
app.get('/', (req, res) => {
  const videosCol = db.getCollection('videos');
  const videos = (videosCol ? videosCol.chain().simplesort('created_at', true).data() : []).slice(0,50).map(v => ({ id: v.$loki, title: v.title, description: v.description, subject: v.subject, tags: v.tags, created_at: v.created_at }));
  res.render('index', { user: req.user || null, videos });
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).send('Missing');
  const hash = await bcrypt.hash(password, 10);
  const users = db.getCollection('users');
  try {
    const user = users.insert({ name: name || '', email, password: hash, created_at: new Date().toISOString() });
    saveDb();
    const token = jwt.sign({ id: user.$loki, email }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/');
  } catch (e) {
    return res.status(400).send('User exists or error');
  }
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const users = db.getCollection('users');
  const user = users.findOne({ email });
  if (!user) return res.status(400).send('Invalid');
  bcrypt.compare(password, user.password).then(match => {
    if (!match) return res.status(400).send('Invalid');
    const token = jwt.sign({ id: user.$loki, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => { res.clearCookie('token'); res.redirect('/'); });

// Upload form
app.get('/upload', authMiddleware, (req, res) => res.render('upload', { user: req.user }));
app.post('/api/upload', authMiddleware, upload.single('video'), (req, res) => {
  const file = req.file;
  const { title, description, tags, subject } = req.body;
  if (!file) return res.status(400).send('No file');
  const videos = db.getCollection('videos');
  videos.insert({ filename: file.filename, originalname: file.originalname, title: title || file.originalname, description: description || '', tags: tags || '', subject: subject || '', uploader: req.user.id, created_at: new Date().toISOString() });
  saveDb();
  res.redirect('/');
});

// List videos JSON
app.get('/api/videos', (req, res) => {
  const videos = (db.getCollection('videos') || { data: () => [] }).chain().simplesort('created_at', true).data().map(v => ({ id: v.$loki, title: v.title, description: v.description, subject: v.subject, tags: v.tags, created_at: v.created_at }));
  res.json(videos);
});

// Video page
app.get('/video/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const videos = db.getCollection('videos');
  const video = videos && videos.get(id);
  if (!video) return res.status(404).send('Not found');
  const commentsCol = db.getCollection('comments');
  const commentsRaw = commentsCol ? commentsCol.find({ video_id: id }) : [];
  const users = db.getCollection('users');
  const comments = commentsRaw.map(c => ({ ...c, name: (users && users.get(c.user_id) && users.get(c.user_id).name) || 'User' }));
  res.render('video', { video: { ...video, id: video.$loki }, comments, user: req.user || null });
});

// Streaming endpoint supporting Range
app.get('/video/:id/stream', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const videos = db.getCollection('videos');
  const video = videos && videos.get(id);
  if (!video) return res.status(404).send('Not found');
  const filePath = path.join(UPLOAD_DIR, video.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  const stat = fs.statSync(filePath);
  const fileSize = stat.size;
  const range = req.headers.range;
  if (range) {
    const parts = range.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
    if (start >= fileSize) {
      res.status(416).send('Requested range not satisfiable');
      return;
    }
    const chunksize = (end - start) + 1;
    const file = fs.createReadStream(filePath, { start, end });
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${fileSize}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': chunksize,
      'Content-Type': 'video/mp4'
    });
    file.pipe(res);
  } else {
    res.writeHead(200, {
      'Content-Length': fileSize,
      'Content-Type': 'video/mp4'
    });
    fs.createReadStream(filePath).pipe(res);
  }
});

// Comments
app.post('/video/:id/comments', authMiddleware, (req, res) => {
  const videoId = parseInt(req.params.id, 10);
  const { content, parent_id } = req.body;
  if (!content) return res.status(400).send('Missing content');
  const comments = db.getCollection('comments');
  comments.insert({ video_id: videoId, user_id: req.user.id, content, parent_id: parent_id ? parseInt(parent_id,10) : null, created_at: new Date().toISOString() });
  saveDb();
  res.redirect(`/video/${videoId}`);
});

// Playlists
app.get('/playlists', (req, res) => {
  const playlistsCol = db.getCollection('playlists');
  const playlists = (playlistsCol ? playlistsCol.chain().simplesort('created_at', true).data() : []).map(p => ({ ...p, id: p.$loki }));
  res.render('playlists', { playlists, user: req.user || null });
});

app.get('/playlists/new', authMiddleware, (req, res) => res.render('playlist_new', { user: req.user }));
app.post('/playlists', authMiddleware, (req, res) => {
  const { name, description } = req.body;
  const playlists = db.getCollection('playlists');
  playlists.insert({ name, owner: req.user.id, description: description || '', created_at: new Date().toISOString(), videos: [] });
  saveDb();
  res.redirect('/playlists');
});

app.post('/playlists/:id/add', authMiddleware, (req, res) => {
  const pid = parseInt(req.params.id, 10);
  const { video_id } = req.body;
  const playlists = db.getCollection('playlists');
  const playlist = playlists.get(pid);
  if (!playlist) return res.status(404).send('Playlist not found');
  playlist.videos = playlist.videos || [];
  if (!playlist.videos.includes(parseInt(video_id, 10))) playlist.videos.push(parseInt(video_id, 10));
  playlists.update(playlist);
  saveDb();
  res.redirect(`/playlists/${pid}`);
});

app.get('/playlists/:id', (req, res) => {
  const pid = parseInt(req.params.id, 10);
  const playlists = db.getCollection('playlists');
  const playlist = playlists.get(pid);
  if (!playlist) return res.status(404).send('Not found');
  const videosCol = db.getCollection('videos');
  const videos = (playlist.videos || []).map(vid => videosCol.get(vid)).filter(Boolean).map(v => ({ ...v, id: v.$loki }));
  res.render('playlist', { playlist: { ...playlist, id: playlist.$loki }, videos, user: req.user || null });
});

// Minimal API for curated syllabus playlists
app.get('/syllabus-playlists', (req, res) => {
  // For prototype, treat playlists with 'syllabus' in name as curated
  const playlistsCol = db.getCollection('playlists');
  const lists = (playlistsCol ? playlistsCol.find({ 'name': { '$regex': /syllabus/i } }) : []);
  res.render('syllabus', { lists: lists.map(l => ({ ...l, id: l.$loki })), user: req.user || null });
});

// Static assets and server start
app.listen(PORT, () => console.log(`KLH Peer Video running on http://localhost:${PORT}`));
