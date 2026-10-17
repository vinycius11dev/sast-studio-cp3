// Exemplos intencionalmente vulneraveis para analise estatica. Nao executar.
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UsuarioRepository {
    private static final String password = "DEMO_SENHA_FICTICIA_1234";

    public static boolean existeUsuario(Connection connection, String userId)
            throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT id FROM users WHERE id = " + userId)) {
            return rows.next();
        }
    }

    public static Process verificarHost(String host) throws IOException {
        return Runtime.getRuntime().exec("ping -n 1 " + host);
    }
}
