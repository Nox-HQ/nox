const express = require('express');

function handleSafe(req, res) {
    const id = parseInt(req.query.id);
    db.query("SELECT * FROM users WHERE id=$1", [id]);
}
