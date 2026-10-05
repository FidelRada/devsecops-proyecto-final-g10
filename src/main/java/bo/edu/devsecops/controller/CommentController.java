package bo.edu.devsecops.controller;

import org.owasp.encoder.Encode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

    @PostMapping(value = "/preview", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> preview(@RequestBody Map<String, String> body) {
        String comment = body.getOrDefault("comment", "");
        // El comentario se codifica para HTML antes de incluirlo en la página.
        String seguro = Encode.forHtml(comment);
        String html = "<html><body><h2>Vista previa</h2><p>" + seguro + "</p></body></html>";
        return ResponseEntity.ok(html);
    }
}
