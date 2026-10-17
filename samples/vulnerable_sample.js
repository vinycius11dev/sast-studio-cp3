/**
 * Amostra de código vulnerável em JavaScript / Node.js para validação SAST
 */
const child_process = require('child_process');

// [JS-R002 / CWE-798] Hardcoded Secrets
const apiKey = "AIzaSyD-FakeApiKeyForNodeJSTesting123";
const dbPassword = "SuperSecretNodePassword!";

function runDynamicCalculation(userFormula) {
    // [JS-R001 / CWE-95] Dangerous Eval
    return eval(userFormula);
}

function pingHost(hostIp) {
    // [JS-R003 / CWE-78] OS Command Injection no Node.js
    child_process.exec("ping -c 1 " + hostIp);
}

function renderUserProfile(userData) {
    // [JS-R004 / CWE-79] Cross-Site Scripting (XSS) via DOM innerHTML
    document.getElementById("profile").innerHTML = "<div>" + userData.bio + "</div>";
}

async function getUser(db, userId) {
    // [JS-R005 / CWE-89] SQL Injection via Template String
    return await db.query(`SELECT * FROM users WHERE id = ${userId}`);
}
