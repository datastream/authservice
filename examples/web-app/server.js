#!/usr/bin/env node
// Simple Express static file server for the OAuth PKCE example app.
//
// Usage:
//   npm start               # serves on http://localhost:3000
//   PORT=8080 npm start     # serves on http://localhost:8080
//
// The BASE_URL in app.js must point to the OAuth server (e.g., http://localhost:8080).
// The OAuth server must be running and configured to allow http://localhost:3000
// as a redirect URI for the "web-app-example" client.

const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from the current directory (index.html, app.js, styles.css, etc.)
app.use(express.static(path.join(__dirname)));

app.listen(PORT, () => {
  console.log(`OAuth PKCE example app running at http://localhost:${PORT}`);
  console.log(`Set BASE_URL in app.js to point to your OAuth server.`);
});
