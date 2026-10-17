package com.fiap.enterprise.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * user_service.java - Serviço de Usuários e Acesso a Dados Java (Amostra do Slide 8).
 *
 * Este arquivo contém exatamente 5 vulnerabilidades identificadas pelo JavaScanner,
 * correspondendo à contagem no Slide 8 do Projeto Integrador FIAP.
 */
public class UserService {

    // [JAVA-R002 / CWE-798] Hardcoded Secrets (2 ocorrências)
    private static final String API_KEY = "sk-live-java-prod-secret-token-998877";
    private String dbPassword = "SecretDatabasePassword123!";

    public void authenticateUser(Connection conn, String user) throws Exception {
        Statement statement = conn.createStatement();
        // [JAVA-R001 / CWE-89] SQL Injection via Statement concatenation (1 ocorrência)
        ResultSet rs = statement.executeQuery("SELECT * FROM users WHERE username = '" + user + "'");
    }

    public void executeHostDiagnostic(String host) throws Exception {
        // [JAVA-R003 / CWE-78] OS Command Injection via Runtime.exec (1 ocorrência)
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public Object restoreSession(FileInputStream fis) throws Exception {
        // [JAVA-R004 / CWE-502] Insecure Deserialization (1 ocorrência)
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }
}
