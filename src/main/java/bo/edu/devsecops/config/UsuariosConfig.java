package bo.edu.devsecops.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.regex.Pattern;

/**
 * Usuarios del laboratorio sin credenciales en el código: los hashes bcrypt llegan por
 * variables de entorno (LAB_ADMIN_PASSWORD_HASH y LAB_USER_PASSWORD_HASH). Si un hash
 * falta o no es bcrypt, ese usuario no se crea y la aplicación arranca igual.
 */
@Configuration
public class UsuariosConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(UsuariosConfig.class);
    private static final Pattern HASH_BCRYPT = Pattern.compile("^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$");

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(
            @Value("${lab.security.admin-password-hash:}") String hashAdmin,
            @Value("${lab.security.user-password-hash:}") String hashUsuario) {
        InMemoryUserDetailsManager usuarios = new InMemoryUserDetailsManager();
        registrar(usuarios, "admin", hashAdmin, "ADMIN");
        registrar(usuarios, "ana", hashUsuario, "USER");
        return usuarios;
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuracion) throws Exception {
        return configuracion.getAuthenticationManager();
    }

    static boolean registrar(InMemoryUserDetailsManager usuarios, String nombre, String hash, String rol) {
        if (hash == null || !HASH_BCRYPT.matcher(hash).matches()) {
            LOGGER.warn("Usuario '{}' no creado: falta su hash bcrypt en el entorno", nombre);
            return false;
        }
        usuarios.createUser(User.withUsername(nombre).password(hash).roles(rol).build());
        return true;
    }
}
