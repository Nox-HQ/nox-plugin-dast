const express = require("express");
const cors = require("cors");

const app = express();

// DAST-001: Missing security headers - responses sent without helmet or security headers
app.get("/", (req, res) => {
    res.send("<html>Welcome</html>");
});

// DAST-002: Insecure CORS configuration - wildcard origin
app.use(cors({ origin: "*", credentials: true }));

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    next();
});

// DAST-003: Missing TLS/HTTPS
const apiUrl = "http://backend.example.com/api";

const https = require("https");
const agent = new https.Agent({ rejectUnauthorized: false });

// DAST-004: Insecure cookie settings
app.get("/session", (req, res) => {
    res.cookie("token", "abc123", { secure: false, httpOnly: false });
    res.send("ok");
});

app.get("/track", (req, res) => {
    document.cookie = "tracker=1; path=/";
    res.send("ok");
});

// DAST-005: Missing rate limiting on API endpoint
app.get("/api/users", (req, res) => {
    res.json({ users: [] });
});

app.post("/api/orders", (req, res) => {
    res.json({ orderId: 1 });
});

// DAST-006: Open redirect
app.get("/redirect", (req, res) => {
    res.redirect(req.query.url);
});

app.listen(3000, () => {
    console.log("Server running");
});
