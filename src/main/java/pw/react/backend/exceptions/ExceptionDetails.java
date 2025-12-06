package pw.react.backend.exceptions;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import pw.react.backend.utils.JsonDateDeserializer;
import pw.react.backend.utils.JsonDateSerializer;

import java.time.LocalDateTime;

@Getter
@Setter
public class ExceptionDetails {
    @JsonDeserialize(using = JsonDateDeserializer.class)
    @JsonSerialize(using = JsonDateSerializer.class)
    private final LocalDateTime timestamp;
    private final HttpStatus status;
    private final String errorMessage;
    private String path;

    public ExceptionDetails(HttpStatus status, String errorMessage) {
        timestamp = LocalDateTime.now();
        this.status = status;
        this.errorMessage = errorMessage;
    }

    public ExceptionDetails(HttpStatus status, String errorMessage, String path) {
        timestamp = LocalDateTime.now();
        this.status = status;
        this.errorMessage = errorMessage;
        this.path = path;
    }
}
