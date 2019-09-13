package net.sunxu.website.service.gateway.filter;

import net.sunxu.website.auth.dto.UserTokenDTO;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class TokenFilter implements GlobalFilter, Ordered {

    private static final String AUTHORIZATION = "Authorization";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getSession()
                .map(webSession -> {
                    UserTokenDTO token = webSession.getAttribute("TOKEN");
                    boolean containsHead = exchange.getRequest().getHeaders()
                            .containsKey(AUTHORIZATION);
                    if (token == null && !containsHead) {
                        return exchange;
                    }
                    var mutate = exchange.getRequest().mutate();
                    if (containsHead) {
                        mutate.headers(hs -> hs.remove(AUTHORIZATION));
                    }
                    if (token != null) {
                        mutate.header(AUTHORIZATION, "Bearer " + token);
                    }
                    return exchange.mutate().request(mutate.build()).build();
                }).flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
