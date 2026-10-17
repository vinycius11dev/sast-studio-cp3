// Exemplos intencionalmente vulneraveis; analisar no SAST, sem executar.
const apiKey = "DEMO_CHAVE_FICTICIA_1234";

function lerPreferencias(userInput) {
  return eval(userInput);
}

// db representa uma conexao MySQL. Nenhum banco e necessario para a analise.
function buscarUsuario(db, userId) {
  return db.query("SELECT id, name FROM users WHERE id = " + userId);
}

module.exports = { apiKey, lerPreferencias, buscarUsuario };
