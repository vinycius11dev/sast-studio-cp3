
const express = require("express");
const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { exec } = require("child_process");
const https = require("https");

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "admin123",
  database: "teste"
});

// 1
app.get("/usuario", (req, res) => {
  const id = req.query.id;

  const sql = "SELECT * FROM usuarios WHERE id = " + id;

  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

// 2
app.get("/pesquisar", (req, res) => {
  const nome = req.query.nome;
  res.send("<h1>Resultado: " + nome + "</h1>");
});

// 3
app.get("/ping", (req, res) => {
  const host = req.query.host;

  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
});

// 4
app.get("/arquivo", (req, res) => {
  const arquivo = req.query.nome;
  const destino = path.join(__dirname, "uploads", arquivo);

  const conteudo = fs.readFileSync(destino, "utf8");
  res.send(conteudo);
});

// 5
app.post("/calcular", (req, res) => {
  const expressao = req.body.expressao;
  const resultado = eval(expressao);

  res.json({ resultado });
});

// 6
function gerarSenhaHash(senha) {
  return crypto
    .createHash("md5")
    .update(senha)
    .digest("hex");
}

// 7
const SECRET_KEY = "123456";
const API_TOKEN = "teste-token-super-secreto";

// 8
const agente = new https.Agent({
  rejectUnauthorized: false
});

// 9
app.get("/redirecionar", (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

// 10
app.post("/login", (req, res) => {
  const usuario = req.body.usuario;
  const senha = req.body.senha;

  if (usuario === "admin" && senha === "123456") {
    return res.json({ autenticado: true });
  }

  res.status(401).json({ erro: "Acesso negado" });
});

app.listen(3000);
