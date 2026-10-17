// Versao corrigida. A consulta usa o contrato de parametros do MySQL/mysql2.
const apiKey = process.env.DEMO_API_KEY;

function lerPreferencias(userInput) {
  return JSON.parse(userInput);
}

function buscarUsuario(db, userId) {
  return db.query("SELECT id, name FROM users WHERE id = ?", [userId]);
}

module.exports = { apiKey, lerPreferencias, buscarUsuario };
