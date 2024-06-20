package pw.react.backend.security.jwt.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pw.react.backend.dao.TokenRepository;
import pw.react.backend.models.Token;

import javax.crypto.SecretKey;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class JwtTokenService implements Serializable {

    @Serial
    private static final long serialVersionUID = -2550185165626007488L;
    private static final Logger log = LoggerFactory.getLogger(JwtTokenService.class);
    private static final String EMPTY_STRING = "";

    private final long expirationMs;
    private final TokenRepository tokenRepository;
    private final SecretKey key;

    private enum Const {
        IP("ip"),
        USER_AGENT("user-agent"),
        X_FORWARDED_FOR("X-FORWARDED-FOR"),
        AUTHORIZATION("Authorization"),
        BEARER("Bearer "),

        ROLES("roles");
        final String value;

        Const(String value) {
            this.value = value;
        }
    }

    public JwtTokenService(String secret, long expirationMs, TokenRepository tokenRepository) {
        this.expirationMs = expirationMs;
        this.tokenRepository = tokenRepository;
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    private Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Boolean hasTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(UserDetails userDetails, HttpServletRequest request) {
        String authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        Map<String, Object> claims = new HashMap<>();
        claims.put(Const.IP.value, getClientIp(request));
        claims.put(Const.USER_AGENT.value, getUserAgent(request));
        claims.put(Const.ROLES.value, authorities);
        log.info("Adding ip:{} and user-agent:{} to the claims.", getClientIp(request), getUserAgent(request));
        return doGenerateToken(claims, userDetails.getUsername());
    }

    private String getClientIpFromToken(String token) {
        return getClaimFromToken(token, claims -> String.valueOf(claims.get(Const.IP.value)));
    }

    private String getClientIp(HttpServletRequest request) {
        String remoteAddr = EMPTY_STRING;
        if (request != null) {
            remoteAddr = request.getHeader(Const.X_FORWARDED_FOR.value);
            if (remoteAddr == null || EMPTY_STRING.equals(remoteAddr)) {
                remoteAddr = request.getRemoteAddr();
            }
        }
        return remoteAddr;
    }

    private String getUserAgent(HttpServletRequest request) {
        String ua = EMPTY_STRING;
        if (request != null) {
            ua = request.getHeader(Const.USER_AGENT.value);
        }
        return ua;
    }

    String getUserAgentFromToken(String token) {
        return getClaimFromToken(token, claims -> String.valueOf(claims.get(Const.USER_AGENT.value)));
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails, HttpServletRequest request) {
        boolean isValidToken = tokenRepository.findByValue(token).isEmpty();
        return getUsernameFromToken(token).equals(userDetails.getUsername()) &&
                hasValidRoles(token, userDetails.getAuthorities()) &&
                !hasTokenExpired(token) &&
                isValidClientIp(token, request) &&
                isValidUserAgent(token, request) &&
                isValidToken;
    }

    private boolean hasValidRoles(String token, Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet())
                .containsAll(getUserRolesFromToken(token));
    }

    Collection<String> getUserRolesFromToken(String token) {
        String roles = getClaimFromToken(token, claims -> String.valueOf(claims.get(Const.ROLES.value)));
        return Arrays.stream(roles.split(",")).toList();
    }

    private boolean isValidUserAgent(String token, HttpServletRequest request) {
        return getUserAgent(request).equals(getUserAgentFromToken(token));
    }

    private boolean isValidClientIp(String token, HttpServletRequest request) {
        return getClientIp(request).equals(getClientIpFromToken(token));
    }

    public boolean invalidateToken(HttpServletRequest request) {
        String requestTokenHeader = request.getHeader(Const.AUTHORIZATION.value);

        if (requestTokenHeader != null && requestTokenHeader.startsWith(Const.BEARER.value)) {
            tokenRepository.save(new Token(requestTokenHeader.substring(Const.BEARER.value.length())));
            return true;
        }
        return false;
    }

    public void removeTokens() {
        tokenRepository.deleteAll();
        log.info("Tokens cleared.");
    }
}