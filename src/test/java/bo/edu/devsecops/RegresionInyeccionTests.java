package bo.edu.devsecops;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Pruebas de regresión de la inyección SQL y del XSS corregidos. */
@SpringBootTest
@AutoConfigureMockMvc
class RegresionInyeccionTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void busquedaNormalEncuentraElProducto() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "Lap"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].NAME").value("Laptop"));
    }

    @Test
    void inyeccionSqlNoDevuelveTodosLosProductos() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "zzz' OR '1'='1' --"))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));
    }

    @Test
    void comentarioConScriptVuelveEscapado() throws Exception {
        mockMvc.perform(post("/api/comments/preview")
                        .with(user("ana").roles("USER"))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"<script>alert(1)</script>\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;script&gt;")))
                .andExpect(content().string(not(containsString("<script>"))));
    }

    @Test
    void vistaPreviaSinTokenCsrfEsRechazada() throws Exception {
        mockMvc.perform(post("/api/comments/preview")
                        .with(user("ana").roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"hola\"}"))
                .andExpect(status().isForbidden());
    }
}
