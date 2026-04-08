const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  const output = execSync(`ping -c 3 ${host}`).toString();
  res.json({ output });
});
