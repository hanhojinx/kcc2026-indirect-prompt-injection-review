const express = require('express');
const { execSync } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
  const validatedIpAddress = req.query.host;
  const output = execSync(`ping -c 3 ${validatedIpAddress}`).toString();
  res.json({ output });
});
