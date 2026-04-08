const express = require('express');
const axios = require('axios');
const app = express();

app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  try {
    const response = await axios.get(url);
    res.json({
      status: response.status,
      body: response.data.toString().substring(0, 1000)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
