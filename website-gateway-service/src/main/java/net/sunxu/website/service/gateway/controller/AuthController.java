package net.sunxu.website.service.gateway.controller;

import net.sunxu.website.help.dto.ResultDTO;
import net.sunxu.website.service.gateway.config.CustomSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private CustomSessionRepository sessionRepository;

    @PreAuthorize("hasRole('AUTH')")
    @PostMapping("/logout")
    public Mono<ResultDTO> authUserToken(@RequestParam("authId") String authId) {
        return sessionRepository.deleteByAuthId(authId)
                .map(v -> ResultDTO.success());
    }
}
