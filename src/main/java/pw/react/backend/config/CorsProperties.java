package pw.react.backend.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.List;

@Profile({"cors"})
@Configuration
@ConfigurationProperties(prefix = "management.endpoints.web.cors")
@Getter
@Setter
public class CorsProperties {
    private List<String> allowedOrigins;
    private List<String> allowedMethods;
    private List<String> allowedHeaders;
    private String allowedOriginPatterns;
}
