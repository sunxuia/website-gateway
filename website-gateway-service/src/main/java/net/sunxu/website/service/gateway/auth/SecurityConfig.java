package net.sunxu.website.service.gateway.auth;

import io.jsonwebtoken.JwtParser;
import java.net.URI;
import java.time.Duration;
import net.sunxu.website.config.feignclient.exception.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtParser jwtParser;

    @Autowired
    private CodeServerAuthenticationConverter codeServerAuthenticationConverter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
//                .pathMatchers("/actuator/**").authenticated()
                .authorizeExchange().anyExchange().permitAll().and()
                .logout().disable()
                .addFilterAt(bearerAuthenticationFilter(), SecurityWebFiltersOrder.FIRST)
                .addFilterAt(codeAuthenticationFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                .addFilterAt(pageAuthenticationFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
                .csrf().disable()
                .exceptionHandling().accessDeniedHandler(((exchange, denied) -> {
                    throw ServiceException.wrapException(HttpStatus.FORBIDDEN, denied);
                })).and()
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    private AuthenticationWebFilter bearerAuthenticationFilter() {
        AuthenticationWebFilter filter = new AuthenticationWebFilter(Mono::just);
        JwtServerAuthenticationConverter converter = new JwtServerAuthenticationConverter(jwtParser);
        filter.setServerAuthenticationConverter(converter);
        filter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/auth/**"));
        return filter;
    }

    private AuthenticationWebFilter codeAuthenticationFilter() {
        AuthenticationWebFilter filter = new AuthenticationWebFilter(Mono::just);
        filter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/login/code"));
        filter.setServerAuthenticationConverter(codeServerAuthenticationConverter);
        filter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
        filter.setAuthenticationSuccessHandler((exchange, auth) -> exchange.getExchange().getSession()
                .flatMap(session -> {
                    session.setMaxIdleTime(Duration.ofDays(14));

                    return exchange.getChain().filter(exchange.getExchange().mutate().request(
                            exchange.getExchange().getRequest().mutate().path("/login/info").build()).build());
                }));
        return filter;
    }

    private AuthenticationWebFilter pageAuthenticationFilter() {
        AuthenticationWebFilter filter = new AuthenticationWebFilter(Mono::just);
        filter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/login/page"));
        filter.setServerAuthenticationConverter(codeServerAuthenticationConverter);
        filter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
        filter.setAuthenticationSuccessHandler((exchange, auth) -> exchange.getExchange().getSession()
                .flatMap(session -> {
                    session.setMaxIdleTime(Duration.ofDays(14));

                    String redirct = session.getAttribute("AUTHORIZED_REDIRECT_TO");
                    if (redirct == null) {
                        redirct = "/login/info";
                    }
                    var response = exchange.getExchange().getResponse();
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(URI.create(redirct));
                    return Mono.empty();
                }));
        return filter;
    }

}
