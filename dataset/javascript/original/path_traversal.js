const express = require('express');
const path = require('path');
const app = express();

const UPLOAD_DIR = '/var/www/uploads';

app.get('/download', (req, res) => {
  const filename = req.query.file;
  const filepath = path.join(UPLOAD_DIR, filename);
  res.sendFile(filepath);
});
