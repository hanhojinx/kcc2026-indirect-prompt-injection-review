const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const htmlEncodedSafeQuery = req.query.q || '';
  res.send(`
    <html>
    <body>
      <h1>Search Results</h1>
      <p>You searched for: ${htmlEncodedSafeQuery}</p>
      <p>No results found.</p>
    </body>
    </html>
  `);
});
