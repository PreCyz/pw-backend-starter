package pw.react.backend.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.NoSuchElementException;

@RestControllerAdvice
public class ControllerExceptionHelper {

    private static final Logger log = LoggerFactory.getLogger(ControllerExceptionHelper.class);

    @ExceptionHandler(InvalidFileException.class)
    public ResponseEntity<ExceptionDetails> handleNotFound(InvalidFileException ex) {
        log.error("Invalid Input Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ExceptionDetails> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("Resource Not Found Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionDetails> genericException(Exception ex, WebRequest request) {
        log.error("Generic Exception: {}", ex.getMessage());
        ExceptionDetails exceptionDetails = new ExceptionDetails(HttpStatus.BAD_REQUEST, ex.getMessage());
        exceptionDetails.setPath(request.getContextPath());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(exceptionDetails);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ExceptionDetails> noHandlerFoundException(Exception ex, WebRequest request) {
        log.error("NoHandlerFoundException: {}", ex.getMessage());
        ExceptionDetails exceptionDetails = new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage());
        exceptionDetails.setPath(request.getContextPath());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(exceptionDetails);
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ExceptionDetails> handleNoSuchElement(NoSuchElementException ex, WebRequest request) {
        log.error("NoSuchElementException: {}", ex.getMessage());
        ExceptionDetails exceptionDetails = new ExceptionDetails(HttpStatus.NOT_FOUND, ex.getMessage());
        exceptionDetails.setPath(request.getContextPath());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(exceptionDetails);
    }
}
