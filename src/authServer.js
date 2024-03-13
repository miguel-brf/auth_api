import cors from 'cors';
import { generateKeyPairSync } from 'crypto';
import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import pemJwk from 'pem-jwk';

function generateAndSaveRS256KeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  fs.writeFileSync('private.key', privateKey);
  fs.writeFileSync('public.key', publicKey);
}

generateAndSaveRS256KeyPair();

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

let refreshTokens = [];

app.post('/refresh', (req, res) => {
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

app.get('/verify', (req, res) => {
  const ACCESS_KEY_PUBLIC = fs.readFileSync('public.key', 'utf-8');
  const jwk = pemJwk.pem2jwk(ACCESS_KEY_PUBLIC);
  jwk.kid = 'unique';
  jwk.use = 'sig';

  const response = {
    keys: [jwk],
  };
  res.json(response);
});

app.delete('/sign-out', (req, res) => {
  console.log(req.body);
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.post('/', (req, res) => {
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
  const ACCESS_KEY_PRIVATE = fs.readFileSync('private.key', 'utf-8');
  console.log(
    '🚀 ~ generateAccessToken ~ ACCESS_KEY_PRIVATE:',
    ACCESS_KEY_PRIVATE
  );

  return jwt.sign(data, ACCESS_KEY_PRIVATE, {
    algorithm: 'RS256',
    expiresIn: '5m',
  });
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '4h' });
}

const PORT = process.env.AUTH_PORT || 3000;

app.listen(PORT, () => {
  console.log(`Authentication server running on port ${PORT}`);
});
