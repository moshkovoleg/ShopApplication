package com.moshkovoleg.model;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public enum Role {
    USER(Set.of(Permission.PRODUCTS_READ,Permission.CART_WRITE)),
    ADMIN(Set.of(Permission.PRODUCTS_READ,Permission.PRODUCTS_WRITE));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getAuthorities(){
        Set<SimpleGrantedAuthority> set = new HashSet<>();
        for (Permission permission : getPermissions()) {
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(permission.getPermission());
            set.add(simpleGrantedAuthority);
        }
        return set;
    }
}
