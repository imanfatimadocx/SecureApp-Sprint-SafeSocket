"use strict";

const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); // ADD THIS

// ── RATE LIMITING FIX ──────────────────────────────────────
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,                  // max 100 requests per IP
    message: 'Too many requests, please try again later.'
});

app.use(limiter);  // Apply to all routes
app.use('/public', express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// ── CSRF TOKEN STORE ───────────────────────────────────────
const csrfTokens = new Map();

const generateCsrfToken = (socketId) => {
    const token = crypto.randomBytes(32).toString('hex');
    csrfTokens.set(socketId, { token, expires: Date.now() + 3600000 });
    return token;
};

const verifyCsrfToken = (socketId, token) => {
    const stored = csrfTokens.get(socketId);
    if (!stored) return false;
    if (Date.now() > stored.expires) { csrfTokens.delete(socketId); return false; }
    return stored.token === token;
};

// ── SOCKET RATE LIMITING ───────────────────────────────────
const messageCounts = new Map();

const checkSocketRateLimit = (socketId) => {
    const now = Date.now();
    const data = messageCounts.get(socketId) || { count: 0, resetAt: now + 60000 };
    if (now > data.resetAt) { data.count = 0; data.resetAt = now + 60000; }
    data.count++;
    messageCounts.set(socketId, data);
    return data.count <= 30; // max 30 messages/min
};

// ── INPUT SANITIZATION ─────────────────────────────────────
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
};

let usernames = {};

io.on('connection', socket => {
    // Send CSRF token on connect
    socket.emit('csrf_token', generateCsrfToken(socket.id));

    socket.on('sendchat', (data, csrfToken) => {
        if (!verifyCsrfToken(socket.id, csrfToken)) {
            socket.emit('error', 'Invalid CSRF token'); return;
        }
        if (!checkSocketRateLimit(socket.id)) {
            socket.emit('error', 'Rate limit exceeded'); return;
        }
        io.emit('updatechat', socket.username, sanitizeInput(data));
    });

    socket.on('adduser', (username, csrfToken) => {
        if (!verifyCsrfToken(socket.id, csrfToken)) {
            socket.emit('error', 'Invalid CSRF token'); return;
        }
        socket.username = sanitizeInput(username);
        usernames[socket.username] = socket.id;
        socket.emit('updatechat', 'Chat Bot', `${socket.username} you have joined the chat`);
        socket.emit('store_username', socket.username);
    });

    socket.on('msg_user', (to_user, from_user, msg, csrfToken) => {
        if (!verifyCsrfToken(socket.id, csrfToken)) {
            socket.emit('error', 'Invalid CSRF token'); return;
        }
        if (socket.username !== from_user) {
            socket.emit('error', 'Unauthorized'); return;
        }
        if (!checkSocketRateLimit(socket.id)) {
            socket.emit('error', 'Rate limit exceeded'); return;
        }
        io.to(usernames[to_user]).emit('msg_user_handle', sanitizeInput(from_user), sanitizeInput(msg));
    });

    socket.on('disconnect', () => {
        delete usernames[socket.username];
        csrfTokens.delete(socket.id);
        messageCounts.delete(socket.id);
    });
});

http.listen(3000, () => console.log('listening on *:3000'));