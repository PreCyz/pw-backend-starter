package pw.react.backend.security.jwt.services;

import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.*;
import org.springframework.web.filter.OncePerRequestFilter;
import pw.react.backend.models.Role;
import pw.react.backend.security.common.AuthenticationService;
import pw.react.backend.security.common.CommonAuthenticationService;
import pw.react.backend.security.jwt.models.CorsDefaultProperties;
import pw.react.backend.security.jwt.models.CorsProperties;

import java.util.List;
import java.util.Optional;

@Profile({"jwt"})
@Import({CorsProperties.class, CorsDefaultProperties.class})
public class WebJwtSecurityConfig {

    private final AuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final OncePerRequestFilter jwtRequestFilter;

    public WebJwtSecurityConfig(AuthenticationEntryPoint jwtAuthenticationEntryPoint,
                                OncePerRequestFilter jwtRequestFilter) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Bean
    public AuthenticationService securityService(AuthenticationManager authenticationManager) {
        return new CommonAuthenticationService(authenticationManager);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties corsProperties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Optional.ofNullable(corsProperties.getAllowedOrigins()).orElseGet(() -> List.of("*")));
        configuration.setAllowedMethods(Optional.ofNullable(corsProperties.getAllowedMethods()).orElseGet(() -> List.of("*")));
        configuration.setAllowedHeaders(Optional.ofNullable(corsProperties.getAllowedHeaders()).orElseGet(() -> List.of("*")));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(Optional.ofNullable(corsProperties.getAllowedOriginPatterns()).orElseGet(() -> "/**"), configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, CorsConfigurationSource corsConfigurationSource) throws Exception {
        return httpSecurity
                //.cors(AbstractHttpConfigurer::disable)
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/**").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                        .anyRequest().hasAnyRole(Role.Value.allRoles().toArray(String[]::new))
                        //.anyRequest().authenticated()
                )
                // Add a filter to validate the tokens with every request
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandlingConfigurer -> exceptionHandlingConfigurer.authenticationEntryPoint(jwtAuthenticationEntryPoint))
                // make sure we use stateless session; session won't be used to store user's state.
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_ADMIN > ROLE_STAFF \n ROLE_STAFF > ROLE_USER";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    @Bean
    public DefaultWebSecurityExpressionHandler customWebSecurityExpressionHandler() {
        DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy());
        return expressionHandler;
    }

}
