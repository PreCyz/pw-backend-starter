package pw.react.backend.exceptions;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.NoSuchElementException;

@RestControllerAdvice
@Slf4j
public class ControllerExceptionHandler {

    @ExceptionHandler(InvalidFileException.class)
    public ResponseEntity<ExceptionDetails> handleNotFound(InvalidFileException ex, WebRequest request) {
        log.error("Invalid Input Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage(), getPath(request)));
    }

    private String getPath(WebRequest request) {
        return ((ServletWebRequest)request).getRequest().getServletPath();
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ExceptionDetails> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        log.error("Resource Not Found Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage(), getPath(request)));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionDetails> genericException(Exception ex, WebRequest request) {
        log.error("Generic Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ExceptionDetails(HttpStatus.BAD_REQUEST, ex.getMessage(), getPath(request)));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ExceptionDetails> noHandlerFoundException(Exception ex, WebRequest request) {
        log.error("NoHandlerFoundException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage(), getPath(request)));
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ExceptionDetails> handleNoSuchElement(NoSuchElementException ex, WebRequest request) {
        log.error("NoSuchElementException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage(), getPath(request)));
    }
}
