package bo.edu.devsecops.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    /**
     * Denegación por defecto: solo la búsqueda de productos, el login y el health son
     * públicos; /api/admin/** y el resto de actuator exigen el rol ADMIN; todo lo demás
     * exige autenticación (HTTP Basic).
     *
     * CSRF queda activo para las peticiones que cambian estado. Solo se exceptúa el login,
     * que no usa sesión ni cookies previas: un navegador no puede reutilizar credenciales
     * de la víctima contra ese endpoint.
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/products/search", "/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        .requestMatchers("/api/admin/**", "/actuator/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/login"))
                .build();
    }
}
