package pw.react.backend.security.jwt.services;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;
import pw.react.backend.dao.*;
import pw.react.backend.models.init.SetupDataLoader;
import pw.react.backend.security.common.CommonUserDetailsService;
import pw.react.backend.security.jwt.filters.JwtAuthenticationEntryPoint;
import pw.react.backend.security.jwt.filters.JwtRequestFilter;

@ConfigurationProperties(prefix = "jwt")
@Profile("jwt")
@Import(WebJwtSecurityConfig.class)
public class JwtConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtConfig.class);

    private String secret;
    private long expirationMs;

    @PostConstruct
    private void init() {
        log.debug("************** JWT properties **************");
        log.debug("JWT secret: {}", secret);
        log.debug("JWT expirationMs: {}", expirationMs);
    }

    @Bean
    public CommonUserDetailsService userDetailsService(UserRepository userRepository) {
        return new CommonUserDetailsService(userRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtTokenService jwtTokenService(TokenRepository tokenRepository) {
        return new JwtTokenService(secret, expirationMs, tokenRepository);
    }

    @Bean
    public OncePerRequestFilter jwtRequestFilter(CommonUserDetailsService commonUserDetailsService, JwtTokenService jwtTokenService) {
        return new JwtRequestFilter(commonUserDetailsService, jwtTokenService);
    }

    @Bean
    public AuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    public SetupDataLoader setupDataLoader(UserRepository userRepository,
                                           RoleRepository roleRepository,
                                           PrivilegeRepository privilegeRepository,
                                           PasswordEncoder passwordEncoder) {
        return new SetupDataLoader(userRepository, roleRepository, privilegeRepository, passwordEncoder);
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }
}

