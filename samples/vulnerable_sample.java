package com.fiap.sast.sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableService {

    // [JAVA-R002 / CWE-798] Hardcoded Secrets
    private static final String API_KEY = "sk-live-java-prod-secret-token-998877";
    private String dbPassword = "SecretDatabasePassword123!";

    public void authenticateUser(Connection conn, String user) throws Exception {
        Statement statement = conn.createStatement();
        // [JAVA-R001 / CWE-89] SQL Injection via Statement concatenation
        ResultSet rs = statement.executeQuery("SELECT * FROM users WHERE username = '" + user + "'");
    }

    public void executeHostDiagnostic(String host) throws Exception {
        // [JAVA-R003 / CWE-78] OS Command Injection via Runtime.exec
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public Object restoreSession(FileInputStream fis) throws Exception {
        // [JAVA-R004 / CWE-502] Insecure Deserialization
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }

    public File retrieveUserDocument(String basePath, String userFilename) {
        // [JAVA-R005 / CWE-22] Path Traversal sem validação canônica
        return new File(basePath, userFilename);
    }
}
