package pw.react.backend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

//@ConfigurationProperties(prefix = "application.springdoc")
public class OpenApiConfig {

    private final Environment environment;
    private String description;
    private String version;
    private String title;

    public OpenApiConfig(Environment environment) {
        this.environment = environment;
    }

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

    public void setDescription(String description) {
        this.description = description;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public Environment getEnvironment() {
        return environment;
    }

    public String getDescription() {
        return description;
    }

    public String getVersion() {
        return version;
    }

    public String getTitle() {
        return title;
    }
}
