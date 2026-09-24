import express from 'express';
const app = express();
app.get('/api/health', (_req, res) => res.send('ok'));
app.post('/api/users', (_req, res) => res.send('created'));
