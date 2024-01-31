package pw.react.backend.security.jwt.models;

import org.springframework.context.annotation.Profile;

@Profile({"!cors"})
public class CorsDefaultProperties extends CorsProperties {
}
