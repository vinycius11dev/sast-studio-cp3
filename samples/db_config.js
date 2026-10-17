/**
 * db_config.js - Configurações de Banco de Dados e Conexões Node.js (Amostra do Slide 8).
 *
 * Este arquivo contém exatamente 8 vulnerabilidades detectáveis pelo JavaScriptScanner,
 * correspondendo à contagem no Slide 8 do Projeto Integrador FIAP.
 */
const child_process = require('child_process');

// [JS-R002 / CWE-798] Hardcoded Secrets (4 ocorrências)
const dbPassword = "ProductionPostgresSecret2026!";
const apiKey = "AIzaSyD-GoogleCloudApiKeyNodeJs123";
const jwtSecret = "MySuperHardcodedJwtSecretToken9988";
const adminToken = "ghp_000000000000000000000000000000000000";

function initDatabaseMigration(migrationScript) {
    // [JS-R001 / CWE-95] Dynamic Code Execution (1 ocorrência)
    eval(migrationScript);
}

function runDbBackup(databaseName) {
    // [JS-R003 / CWE-78] OS Command Injection (1 ocorrência)
    child_process.exec("pg_dump -U postgres " + databaseName);
}

function renderDbDiagnostic(statusMessage) {
    // [JS-R004 / CWE-79] Cross-Site Scripting (XSS) (1 ocorrência)
    document.getElementById("status-box").innerHTML = "<div>" + statusMessage + "</div>";
}

async function queryUserProfile(dbPool, userId) {
    // [JS-R005 / CWE-89] SQL Injection via Template Literal (1 ocorrência)
    return await dbPool.query(`SELECT * FROM db_users WHERE id = ${userId}`);
}
