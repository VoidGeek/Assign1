const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const router = express.Router();

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const blogSchema = new mongoose.Schema({
  id: String,
  blogTitle: String,
  blogContent: String,
  authorId: { type: String, index: true }, // Assuming authorId is a string
  subscribedUserId: String,
  activeSubscriber: Boolean
});

const Blog = mongoose.model('Blog', blogSchema);

app.use(express.json());

app.use('/api', router);

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decodedToken) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.userId = decodedToken.userId; // Assuming the decoded token contains userId
    next();
  });
};

router.post('/register', async (req, res) => {
  try {
    const { username, password, } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid username or password' });

    const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET);
    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/blogs', authenticateToken, async (req, res) => {
  try {
    const { id, blogTitle, blogContent, subscribedUserId, activeSubscriber,authorId } = req.body;
    const newBlog = new Blog({ id, blogTitle, blogContent, authorId, subscribedUserId, activeSubscriber });
    await newBlog.save();
    res.status(201).json(newBlog);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/blogs/:authorId', authenticateToken, async (req, res) => {
  try {
    const blogs = await Blog.find({ authorId });
    if (!blogs || blogs.length === 0) {
      return res.status(404).json({ error: 'Blogs not found for this author' });
    }
    res.json(blogs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
