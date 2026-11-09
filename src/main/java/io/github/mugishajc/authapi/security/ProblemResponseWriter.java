package io.github.mugishajc.authapi.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;

/**
 * Writes 401 and 403 responses from the filter chain in the same problem+json
 * shape the controllers use, instead of Spring's default empty body.
 */
@Component
public class ProblemResponseWriter {

    private final ObjectMapper objectMapper;

    public ProblemResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, e) -> write(response, HttpStatus.UNAUTHORIZED, "Unauthorized",
                "A valid access token is required", request.getRequestURI());
    }

    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> write(response, HttpStatus.FORBIDDEN, "Forbidden",
                "You do not have permission to perform this action", request.getRequestURI());
    }

    private void write(HttpServletResponse response, HttpStatus status, String title, String detail, String path)
            throws IOException {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        problem.setInstance(URI.create(path));
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        if (status == HttpStatus.UNAUTHORIZED) {
            response.setHeader("WWW-Authenticate", "Bearer");
        }
        objectMapper.writeValue(response.getOutputStream(), problem);
    }
}
