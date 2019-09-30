package net.sunxu.website.service.gateway.auth;

import static net.sunxu.website.service.gateway.util.ConstValueDef.TOKEN_ATTR_NAME;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.sunxu.website.auth.feignclient.AuthFeignClient;
import net.sunxu.website.help.util.ThreadPoolHelpUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class CodeServerAuthenticationConverter implements ServerAuthenticationConverter {

    @Autowired
    @Lazy
    private AuthFeignClient authFeignClient;

    @Autowired
    @Lazy
    private JwtParser jwtParser;

    private ExecutorService authorizationExecutor = ThreadPoolHelpUtils.newFixedThreadExecutor("authorization", 8);

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        var queryParams = exchange.getRequest().getQueryParams();
        if (queryParams.containsKey("code")) {
            String code = queryParams.getFirst("code");
            return Mono.fromFuture(CompletableFuture
                    .supplyAsync(() -> authFeignClient.postForToken(code), authorizationExecutor))
                    .zipWith(exchange.getSession())
                    .flatMap(t -> {
                        var token = t.getT1();
                        var session = t.getT2();

                        var claims = parseClaims(token.getToken());
                        var res = Mono.justOrEmpty(createAuthentication(claims, token.getToken()));

                        session.getAttributes().put(TOKEN_ATTR_NAME, token);
                        session.getAttributes().put("AUTH_ID", token.getAuthId());

                        var uri = exchange.getRequest().getURI();
                        exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin",
                                uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort());
                        return res;
                    });
        }
        return Mono.empty();
    }

    private Claims parseClaims(String token) {
        try {
            return jwtParser.parseClaimsJws(token).getBody();
        } catch (Exception err) {
            log.warn("error while parse token: {}\n exception: {}", token, err.toString());
            throw new RuntimeException(err);
        }
    }

    @SuppressWarnings("unchecked")
    private Authentication createAuthentication(Claims claims, String token) {
        UserPrincipal principal = new UserPrincipal();
        principal.setId(claims.get("id", Long.class));
        principal.setUserName(claims.get("name", String.class));
        principal.setService(false);
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
