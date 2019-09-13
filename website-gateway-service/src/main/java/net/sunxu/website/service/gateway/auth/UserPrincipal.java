package net.sunxu.website.service.gateway.auth;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class UserPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = -1L;

    private Long id;

    private String userName;

    private Collection<String> roles;

    private boolean service;

    private String principalName;

    @Override
    public String getName() {
        if (principalName == null) {
            principalName = (service ? "SERVICE_" : "USER_") + id;
        }
        return principalName;
    }
}
