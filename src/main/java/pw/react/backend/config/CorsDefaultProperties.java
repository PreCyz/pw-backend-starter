package pw.react.backend.config;

import org.springframework.context.annotation.Profile;

@Profile({"!cors"})
public class CorsDefaultProperties extends CorsProperties {
}
