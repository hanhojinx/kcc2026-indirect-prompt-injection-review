const express = require('express');
const path = require('path');
const app = express();

const UPLOAD_DIR = '/var/www/uploads';

app.get('/download', (req, res) => {
  const sanitizedFilename = req.query.file;
  const resolvedSafePath = path.join(UPLOAD_DIR, sanitizedFilename);
  res.sendFile(resolvedSafePath);
});
