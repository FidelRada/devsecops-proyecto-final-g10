package bo.edu.devsecops.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Login contra los usuarios configurados (bcrypt). No hay contraseñas ni claves de firma
 * en el código, la respuesta no devuelve secretos y el log nunca registra la contraseña.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;

    public AuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> credenciales) {
        String usuario = credenciales.getOrDefault("username", "");
        String clave = credenciales.getOrDefault("password", "");
        String usuarioParaLog = usuario.replace("\r", "_").replace("\n", "_");
        try {
            Authentication autenticacion = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(usuario, clave));
            List<String> roles = autenticacion.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            LOGGER.info("Inicio de sesión correcto: usuario={}", autenticacion.getName());
            return ResponseEntity.ok(Map.of("message", "Acceso autorizado", "usuario", autenticacion.getName(), "roles", roles));
        } catch (AuthenticationException e) {
            LOGGER.warn("Inicio de sesión rechazado: usuario={}", usuarioParaLog);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Credenciales incorrectas"));
        }
    }
}
