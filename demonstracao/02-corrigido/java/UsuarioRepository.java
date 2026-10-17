// Versao corrigida dos mesmos exemplos para comparar no SAST.
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;

public class UsuarioRepository {
    private static final String password = System.getenv("DEMO_DB_PASSWORD");

    public static boolean existeUsuario(Connection connection, String userId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM users WHERE id = ?")) {
            statement.setString(1, userId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    public static Process verificarHost(String host) throws IOException {
        if (!Set.of("127.0.0.1", "::1").contains(host)) {
            throw new IllegalArgumentException("Host fora da lista permitida");
        }
        return new ProcessBuilder("ping", "-n", "1", host).start();
    }
}
