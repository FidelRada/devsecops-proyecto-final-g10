package bo.edu.devsecops;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DevSecOpsLabApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void productSearchIsAvailable() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "Laptop"))
                .andExpect(status().isOk());
    }

    @Test
    void adminEndpointRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/admin/users/1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminEndpointRejectsNonAdminUsers() throws Exception {
        mockMvc.perform(get("/api/admin/users/1").with(user("ana").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminEndpointAllowsAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users/1").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    void healthIsPublicAndOtherActuatorEndpointsAreNot() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        mockMvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
    }
}
