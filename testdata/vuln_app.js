const crypto = require('crypto');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

// TRIAGE-001: Critical - eval and child_process with user input
function dangerousExec(userInput) {
    eval(userInput);
    child_process.exec("cmd " + userInput);
}

// TRIAGE-002: Missing input validation on external data
function handleRequest(req, res) {
    const name = req.body.name;
    const id = req.query.id;
    const slug = req.params.slug;
    res.json({ name, id, slug });
}

// TRIAGE-003: Security TODOs
// TODO: security fix needed for CSRF protection
function legacyEndpoint() {
    document.write("<div>unsafe</div>");
}

// TRIAGE-004: Security-relevant code
const token = jwt.sign({ id: 1 }, 'secret');
const hash = crypto.createHash('sha256');
