import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

let refreshTokens = [];

app.post('/token', (req, res) => {
  const refreshToken = req.body.token;

  if (refreshToken === undefined) return res.sendStatus(401);

  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const data = genDataForAccessToken(user.name);
    const accessToken = generateAccessToken(data);
    res.json({ accessToken });
  });
});

app.delete('/logout', (req, res) => {
  console.log(req.body);
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.post('/login', (req, res) => {
  // Authenticate User

  const username = req.body.username;
  const data = genDataForAccessToken(username);
  const accessToken = generateAccessToken(data);
  const refreshToken = generateRefreshToken(data);

  refreshTokens.push(refreshToken);

  res.json({ accessToken, refreshToken });
});

function genDataForAccessToken(name) {
  return { name, scope: process.env.SCOPE };
}

function generateAccessToken(data) {
  return jwt.sign(data, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '4h' });
}

const PORT = process.env.AUTH_PORT || 3000;

app.listen(PORT, () => {
  console.log(`Authentication server running on port ${PORT}`);
});
