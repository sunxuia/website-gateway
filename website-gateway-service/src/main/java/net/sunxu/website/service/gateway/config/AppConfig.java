package net.sunxu.website.service.gateway.config;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import java.time.Duration;
import net.sunxu.website.config.feignclient.AppServiceAdaptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.web.server.session.SpringSessionWebSessionStore;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.server.session.WebSessionIdResolver;
import org.springframework.web.server.session.WebSessionManager;

@Configuration
public class AppConfig {

    @Bean(WebHttpHandlerBuilder.WEB_SESSION_MANAGER_BEAN_NAME)
    public WebSessionManager webSessionManager(ReactiveSessionRepository<? extends Session> repository) {
        var sessionStore = new SpringSessionWebSessionStore<>(repository);
        var manager = new DefaultWebSessionManager();
        manager.setSessionStore(sessionStore);
        manager.setSessionIdResolver(webSessionIdResolver());
        return manager;
    }

    private WebSessionIdResolver webSessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
        resolver.setCookieName("sid");
        resolver.setCookieMaxAge(Duration.ofDays(365));
        return resolver;
    }

    @Bean
    public JwtParser serviceJwtParser(AppServiceAdaptor appService) {
        JwtParser parser = Jwts.parser();
        try {
            var publicKey = appService.getPublicKey();
            parser.setSigningKey(publicKey.readPublicKey());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return parser;
    }
}
