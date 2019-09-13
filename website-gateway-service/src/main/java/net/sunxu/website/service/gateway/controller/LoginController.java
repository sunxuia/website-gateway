package net.sunxu.website.service.gateway.controller;

import java.time.Duration;
import javax.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import net.sunxu.website.service.gateway.auth.UserPrincipal;
import net.sunxu.website.service.gateway.dto.UserInfoDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class LoginController {

    @Resource(name = "stringReactiveRedisTemplate")
    private ReactiveRedisTemplate<String, String> redisTemplate;

    @Value("${website.status-redirect-url}")
    private String statusRedirectUrl;

    @Value("${spring.application.name}")
    private String applicationName;


    @GetMapping("/login/info")
    public Mono<UserInfoDTO> getInfo() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.getPrincipal() instanceof UserPrincipal)
                .map(auth -> {
                    var user = (UserPrincipal) auth.getPrincipal();
                    var res = new UserInfoDTO();
                    res.setId(user.getId());
                    res.setName(user.getUserName());
                    res.setRoles(user.getRoles());
                    return res;
                });
    }

    @GetMapping("/login/status")
    public Mono<UserInfoDTO> getStatus(ServerWebExchange exchange) {
        return getInfo()
                // 未登录的重定向到auth 的登录页
                .switchIfEmpty(Mono.defer(() -> {
                    String redirect = statusRedirectUrl
                            + "?service=" + applicationName
                            + "&redirect=" + exchange.getRequest().mutate().path("/login/code").build()
                            .getURI();
                    var response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().add("Location", redirect);
                    return Mono.empty();
                }));
    }

    @GetMapping("/login/redirect")
    public Mono<Void> redirect(@RequestParam("redirect") String redirect, ServerWebExchange exchange) {
        String redirectUrl = statusRedirectUrl
                + "?service=" + applicationName
                + "&redirect=" + exchange.getRequest().mutate().path("/login/page").build()
                .getURI();
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().add("Location", redirectUrl);
        return exchange.getSession().flatMap(session -> {
            session.setMaxIdleTime(Duration.ofMinutes(10));
            session.getAttributes().put("AUTHORIZED_REDIRECT_TO", redirect);
            return Mono.empty();
        });
    }

}
