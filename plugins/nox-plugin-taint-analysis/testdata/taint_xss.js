const express = require('express');

function handleMessage(req, res) {
    const msg = req.query.message;
    const el = document.getElementById('output');
    el.innerHTML = msg;
}
