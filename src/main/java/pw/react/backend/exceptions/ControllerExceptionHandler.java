package pw.react.backend.exceptions;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class ControllerExceptionHandler {

    @ExceptionHandler(InvalidFileException.class)
    public ResponseEntity<ExceptionDetails> handleNotFound(InvalidFileException ex, ServletWebRequest request) {
        log.error("Invalid Input Exception: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(
                        HttpStatus.NOT_FOUND,
                        ex.getMessage(),
                        request.getRequest().getServletPath()
                ));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ExceptionDetails> handleResourceNotFoundException(ResourceNotFoundException ex, ServletWebRequest request) {
        log.error("Resource Not Found Exception: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(
                        HttpStatus.NOT_FOUND,
                        ex.getMessage(),
                        request.getRequest().getServletPath()
                ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionDetails> genericException(Exception ex, ServletWebRequest request) {
        log.error("Generic Exception: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(new ExceptionDetails(
                        HttpStatus.UNPROCESSABLE_ENTITY,
                        ex.getMessage(),
                        request.getRequest().getServletPath())
                );
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ExceptionDetails> noHandlerFoundException(Exception ex, ServletWebRequest request) {
        log.error("NoHandlerFoundException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(
                        HttpStatus.NOT_FOUND,
                        ex.getMessage(),
                        request.getRequest().getServletPath()
                ));
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ExceptionDetails> handleNoSuchElement(NoSuchElementException ex, ServletWebRequest request) {
        log.error("NoSuchElementException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ExceptionDetails(
                        HttpStatus.NOT_FOUND,
                        ex.getMessage(),
                        request.getRequest().getServletPath()
                ));
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<ExceptionDetails> handleValidationExceptions(HandlerMethodValidationException ex, ServletWebRequest request) {
        String errMsg = ex.getParameterValidationResults()
                .stream()
                .flatMap(e -> e.getResolvableErrors().stream())
                .map(MessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(","));
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ExceptionDetails(
                        HttpStatus.BAD_REQUEST,
                        errMsg,
                        request.getRequest().getServletPath()
                ));
    }
}
