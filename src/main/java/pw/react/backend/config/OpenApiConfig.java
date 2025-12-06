package pw.react.backend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import lombok.*;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

//@ConfigurationProperties(prefix = "application.springdoc")
@RequiredArgsConstructor
@Getter
@Setter
public class OpenApiConfig {

    private final Environment environment;
    private String description;
    private String version;
    private String title;

    @Bean
    public OpenAPI openAPI() {
        return createOpenApi();
    }

    private OpenAPI createOpenApi() {
        String fullDescription = description +
                "\nActive profiles: " + String.join(",", environment.getActiveProfiles());
        return new OpenAPI()
                .info(new Info()
                        .title(title)
                        .version(version)
                        .description(fullDescription)
                        .termsOfService("http://swagger.io/terms/")
                        .license(new License().name("Apache 2.0").url("http://springdoc.org")));
    }
}
