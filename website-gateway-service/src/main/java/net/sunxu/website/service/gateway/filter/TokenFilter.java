package net.sunxu.website.service.gateway.filter;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import lombok.extern.slf4j.Slf4j;
import net.sunxu.website.auth.dto.UserTokenDTO;
import net.sunxu.website.auth.feignclient.AuthFeignClient;
import net.sunxu.website.help.util.ThreadPoolHelpUtils;
import net.sunxu.website.service.gateway.util.ConstValueDef;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class TokenFilter implements GlobalFilter, Ordered {

    private static final String AUTHORIZATION = "Authorization";

    @Autowired
    @Lazy
    private AuthFeignClient authFeignClient;

    private ExecutorService threadPool = ThreadPoolHelpUtils.newFixedThreadExecutor("refresh-token", 8);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getSession()
                .flatMap(webSession -> {
                    UserTokenDTO userToken = webSession.getAttribute(ConstValueDef.TOKEN_ATTR_NAME);
                    boolean containsHead = exchange.getRequest().getHeaders().containsKey(AUTHORIZATION);
                    if (userToken == null && !containsHead) {
                        return chain.filter(exchange);
                    }
                    var res = refreshToken(userToken, webSession);
                    var requestMutate = exchange.getRequest().mutate();
                    if (containsHead) {
                        requestMutate.headers(hs -> hs.remove(AUTHORIZATION));
                    }
                    return res.map(token -> requestMutate.header(AUTHORIZATION, "Bearer " + token.getToken()))
                            .then(Mono.defer(() -> chain.filter(
                                    exchange.mutate().request(requestMutate.build()).build())));
                });
    }

    @Override
    public int getOrder() {
        return 0;
    }

    private Mono<UserTokenDTO> refreshToken(UserTokenDTO token, WebSession session) {
        // 没有token/ token 未过期
        if (token == null || token.getTokenExpire() > System.currentTimeMillis()) {
            return Mono.justOrEmpty(token);
        }
        // refresh token 已经过期
        if (token.getRefreshTokenExpire() > System.currentTimeMillis()) {
            session.getAttributes().remove(ConstValueDef.TOKEN_ATTR_NAME);
            return Mono.empty();
        }
        // 更新token 并保存到session
        return Mono.fromFuture(CompletableFuture.supplyAsync(() -> {
            try {
                var newToken = authFeignClient.postForRefreshToken(token.getRefreshToken());
                if (newToken == null) {
                    session.getAttributes().remove(ConstValueDef.TOKEN_ATTR_NAME);
                } else {
                    session.getAttributes().put(ConstValueDef.TOKEN_ATTR_NAME, newToken);
                }
                return newToken;
            } catch (Exception err) {
                log.error("Exception while get refresh token: {}", err.toString());
                return null;
            }
        }, threadPool));
    }
}
