package net.sunxu.website.service.gateway.config;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import net.sunxu.website.service.gateway.config.CustomSessionRepository.RedisSession;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.session.MapSession;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * Modified from ReactiveRedisOperationsSessionRepository, add index for user id
 */
@Component
public class CustomSessionRepository implements ReactiveSessionRepository<RedisSession> {

    private static final String CREATION_TIME_KEY = "creationTime";

    private static final String LAST_ACCESSED_TIME_KEY = "lastAccessedTime";

    private static final String MAX_INACTIVE_INTERVAL_KEY = "maxInactiveInterval";

    private static final String ATTRIBUTE_PREFIX = "sessionAttr:";

    private static final String NAMESPACE = "spring:session:";

    private static final String AUTH_ID = "AUTH_ID";

    private static final Duration INACTIVE_INTERVAL = Duration.ofMinutes(5);

    private static String getAttributeKey(String attributeName) {
        return ATTRIBUTE_PREFIX + attributeName;
    }

    private static String getSessionKey(String sessionId) {
        return NAMESPACE + "sessions:" + sessionId;
    }

    private static String getAuthIdKey(String id) {
        return NAMESPACE + "AUTH_ID_INDEX:" + id;
    }

    private final ReactiveRedisOperations<String, Object> sessionRedisOperations;

    public CustomSessionRepository(ObjectProvider<ReactiveRedisConnectionFactory> redisConnectionFactory) {
        sessionRedisOperations = createSessionRedisOperations(redisConnectionFactory);
    }

    private ReactiveRedisOperations<String, Object> createSessionRedisOperations(
            ObjectProvider<ReactiveRedisConnectionFactory> redisConnectionFactory) {
        var factory = redisConnectionFactory.getObject();
        RedisSerializer<String> keySerializer = new StringRedisSerializer();
        RedisSerializer<Object> defaultSerializer = new JdkSerializationRedisSerializer(getClass().getClassLoader());
        RedisSerializationContext<String, Object> serializationContext = RedisSerializationContext
                .<String, Object>newSerializationContext(defaultSerializer)
                .key(keySerializer).hashKey(keySerializer).build();
        return new ReactiveRedisTemplate<>(factory, serializationContext);
    }

    @Override
    public Mono<RedisSession> createSession() {
        return Mono.defer(() -> {
            RedisSession session = new RedisSession();
            session.setMaxInactiveInterval(INACTIVE_INTERVAL);
            return Mono.just(session);
        });
    }

    @Override
    public Mono<Void> save(RedisSession session) {
        Mono<Void> result = session.saveChangeSessionId()
                .and(session.saveDelta())
                .and((s) -> {
                    session.isNew = false;
                    s.onComplete();
                });
        if (session.getAttribute(AUTH_ID) != null) {
            String indexKey = getAuthIdKey(session.getAttribute(AUTH_ID));
            result = result.and(sessionRedisOperations.delete(indexKey))
                    .and(sessionRedisOperations.opsForValue().set(indexKey, session.getId()))
                    .then(sessionRedisOperations.expire(indexKey, session.getMaxInactiveInterval()))
                    .then();
        }
        if (session.isNew) {
            return result;
        } else {
            String sessionKey = getSessionKey(
                    session.hasChangedSessionId() ? session.originalSessionId : session.getId());
            var ret = result;
            return sessionRedisOperations.hasKey(sessionKey)
                    .flatMap(exist -> exist ? ret : Mono.empty());
        }
    }

    @Override
    public Mono<RedisSession> findById(String id) {
        String sessionKey = getSessionKey(id);

        // @formatter:off
        return sessionRedisOperations.opsForHash().entries(sessionKey)
                .collectMap(e -> e.getKey().toString(), Map.Entry::getValue)
                .filter(map -> !map.isEmpty())
                .map(map -> {
                    MapSession cache = new MapSession(id);
                    cache.setCreationTime(Instant.ofEpochMilli((long) map.get(CREATION_TIME_KEY)));
                    cache.setLastAccessedTime(Instant.ofEpochMilli((long) map.get(LAST_ACCESSED_TIME_KEY)));
                    cache.setMaxInactiveInterval(Duration.ofSeconds((int) map.get(MAX_INACTIVE_INTERVAL_KEY)));
                    map.forEach((name, value) -> {
                        if (name.startsWith(ATTRIBUTE_PREFIX)) {
                            cache.setAttribute(name.substring(ATTRIBUTE_PREFIX.length()), value);
                        }
                    });
                    return cache;
                }).filter(cache -> !cache.isExpired())
                .map(RedisSession::new)
                .switchIfEmpty(deleteById(id).then(Mono.empty()));
        // @formatter:on
    }

    @Override
    public Mono<Void> deleteById(String id) {
        String sessionKey = getSessionKey(id);
        return sessionRedisOperations.opsForHash()
                .get(sessionKey, getAttributeKey(AUTH_ID))
                .cast(String.class)
                .flatMap(authId -> sessionRedisOperations.delete(getAuthIdKey(authId)))
                .and(sessionRedisOperations.delete(getSessionKey(id)));
    }

    public Mono<Void> deleteByAuthId(String authId) {
        String indexKey = getAuthIdKey(authId);
        return sessionRedisOperations.delete(
                sessionRedisOperations.opsForValue()
                        .get(authId)
                        .cast(String.class)
                        .map(CustomSessionRepository::getSessionKey))
                .then(sessionRedisOperations.delete(indexKey))
                .then();
    }

    public final class RedisSession implements Session {

        private final MapSession cached;

        private final Map<String, Object> delta = new HashMap<>();

        private boolean isNew;

        private String originalSessionId;

        RedisSession() {
            this(new MapSession());
            this.delta.put(CREATION_TIME_KEY, getCreationTime().toEpochMilli());
            this.delta.put(MAX_INACTIVE_INTERVAL_KEY, (int) getMaxInactiveInterval().getSeconds());
            this.delta.put(LAST_ACCESSED_TIME_KEY, getLastAccessedTime().toEpochMilli());
            this.isNew = true;
            this.flushImmediateIfNecessary();
        }

        RedisSession(MapSession mapSession) {
            Assert.notNull(mapSession, "mapSession cannot be null");
            this.cached = mapSession;
            this.originalSessionId = mapSession.getId();
        }

        @Override
        public String getId() {
            return this.cached.getId();
        }

        @Override
        public String changeSessionId() {
            return this.cached.changeSessionId();
        }

        @Override
        public <T> T getAttribute(String attributeName) {
            return this.cached.getAttribute(attributeName);
        }

        @Override
        public Set<String> getAttributeNames() {
            return this.cached.getAttributeNames();
        }

        @Override
        public void setAttribute(String attributeName, Object attributeValue) {
            this.cached.setAttribute(attributeName, attributeValue);
            putAndFlush(getAttributeKey(attributeName), attributeValue);
        }

        @Override
        public void removeAttribute(String attributeName) {
            this.cached.removeAttribute(attributeName);
            putAndFlush(getAttributeKey(attributeName), null);
        }

        @Override
        public Instant getCreationTime() {
            return this.cached.getCreationTime();
        }

        @Override
        public void setLastAccessedTime(Instant lastAccessedTime) {
            this.cached.setLastAccessedTime(lastAccessedTime);
            putAndFlush(LAST_ACCESSED_TIME_KEY, getLastAccessedTime().toEpochMilli());
        }

        @Override
        public Instant getLastAccessedTime() {
            return this.cached.getLastAccessedTime();
        }

        @Override
        public void setMaxInactiveInterval(Duration interval) {
            this.cached.setMaxInactiveInterval(interval);
            putAndFlush(MAX_INACTIVE_INTERVAL_KEY, (int) getMaxInactiveInterval().getSeconds());
        }

        @Override
        public Duration getMaxInactiveInterval() {
            return this.cached.getMaxInactiveInterval();
        }

        @Override
        public boolean isExpired() {
            return this.cached.isExpired();
        }

        private boolean hasChangedSessionId() {
            return !getId().equals(this.originalSessionId);
        }

        private void flushImmediateIfNecessary() {
//            if (REDIS_FLUSH_MODE == RedisFlushMode.IMMEDIATE) {
//                saveDelta();
//            }
        }

        private void putAndFlush(String a, Object v) {
            this.delta.put(a, v);
            flushImmediateIfNecessary();
        }

        private Mono<Void> saveDelta() {
            if (this.delta.isEmpty()) {
                return Mono.empty();
            }

            String sessionKey = getSessionKey(getId());
            Mono<Boolean> update = sessionRedisOperations
                    .opsForHash().putAll(sessionKey, this.delta);
            Mono<Boolean> setTtl = sessionRedisOperations
                    .expire(sessionKey, getMaxInactiveInterval());

            return update.and(setTtl).and((s) -> {
                this.delta.clear();
                s.onComplete();
            }).then();
        }

        private Mono<Void> saveChangeSessionId() {
            if (!hasChangedSessionId()) {
                return Mono.empty();
            }

            String sessionId = getId();

            Publisher<Void> replaceSessionId = (s) -> {
                this.originalSessionId = sessionId;
                s.onComplete();
            };

            if (this.isNew) {
                return Mono.from(replaceSessionId);
            } else {
                String originalSessionKey = getSessionKey(this.originalSessionId);
                String sessionKey = getSessionKey(sessionId);

                return sessionRedisOperations.rename(originalSessionKey, sessionKey)
                        .and(replaceSessionId);
            }
        }

    }
}
