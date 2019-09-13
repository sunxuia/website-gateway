package net.sunxu.website.service.gateway.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.sunxu.website.help.util.ObjectHelpUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
public class JwtServerAuthenticationConverter implements ServerAuthenticationConverter {

    private final JwtParser parser;

    public JwtServerAuthenticationConverter(JwtParser parser) {
        this.parser = parser;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.defer(() -> {
            var headers = exchange.getRequest().getHeaders().get("Authorization");
            if (headers != null) {
                for (String header : headers) {
                    if (header.startsWith("Bearer ")) {
                        String token = header.substring(7);
                        var claims = parseClaims(token);
                        if (claims != null) {
                            return Mono.justOrEmpty(createAuthentication(claims, token));
                        }
                    }
                }
            }
            return Mono.empty();
        });
    }

    private Claims parseClaims(String token) {
        try {
            return parser.parseClaimsJws(token).getBody();
        } catch (Exception err) {
            log.warn("error while parse token: {}", err.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Authentication createAuthentication(Claims claims, String token) {
        UserPrincipal principal = new UserPrincipal();
        principal.setId(claims.get("id", Long.class));
        principal.setUserName(claims.get("name", String.class));
        principal.setService(ObjectHelpUtils.nvl(claims.get("service", Boolean.class), Boolean.FALSE));
        var roles = (List<String>) claims.get("roles", List.class);
        if (roles == null) {
            principal.setRoles(Collections.emptySet());
        } else {
            principal.setRoles(Set.copyOf(roles));
        }
        Set<GrantedAuthority> auths = principal.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        return new UsernamePasswordAuthenticationToken(principal, token, auths);
    }
}
