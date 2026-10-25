// Intentionally vulnerable JavaScript/TypeScript test fixture
const child_process = require("child_process");
const fs = require("fs");

function runBackup(dest) {
    // VULNERABILITY: Command Injection
    child_process.exec(`tar -czf backup.tar.gz ${dest}`);
}

function getUser(db, userId) {
    // VULNERABILITY: SQL Injection
    return db.query(`SELECT * FROM users WHERE id = '${userId}'`);
}

function readProfile(filename) {
    // VULNERABILITY: Path Traversal
    return fs.readFile(`/var/app/data/${filename}`);
}

function renderBanner(element, userHtml) {
    // VULNERABILITY: XSS
    element.innerHTML = userHtml;
}

// Express route entry points
app.get("/api/user", getUser);
app.post("/api/backup", runBackup);

module.exports = { runBackup, getUser, readProfile, renderBanner };
