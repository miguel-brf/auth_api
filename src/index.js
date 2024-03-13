import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const posts = [
  {
    username: 'Miguel',
    title: 'Post 1',
  },
  {
    username: 'Test',
    title: 'Post 2',
  },
];

app.get('/posts', authenticateToken, (req, res) => {
  const username = req?.user?.name;
  console.log(req.user);
  res.json(posts.filter((post) => post.username === username));
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (token === undefined) return res.sendStatus(401);

  const ACCESS_KEY_PUBLIC = fs.readFileSync('public.key', 'utf-8');
  jwt.verify(token, ACCESS_KEY_PUBLIC, (err, data) => {
    if (err || data.scope !== process.env.SCOPE) return res.sendStatus(403);

    req.user = data;
    next();
  });
}

app.get('/hello', (req, res) => {
  res.sendStatus(418);
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
