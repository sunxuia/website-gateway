package net.sunxu.website.service.gateway.dto;

import java.io.Serializable;
import java.util.Collection;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class UserInfoDTO implements Serializable {

    private static long serialVersionUID = -1L;

    private Long id;

    private String name;

    private Collection<String> roles;

}
