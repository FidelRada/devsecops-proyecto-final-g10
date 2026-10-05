package bo.edu.devsecops.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    /** Consulta fija: el texto del usuario viaja solo como parámetro enlazado, nunca dentro del SQL. */
    private static final String CONSULTA = "SELECT id, name, price FROM products WHERE name LIKE ?";

    private final JdbcTemplate jdbcTemplate;

    public ProductController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam(defaultValue = "") String name) {
        return jdbcTemplate.queryForList(CONSULTA, "%" + name + "%");
    }
}
