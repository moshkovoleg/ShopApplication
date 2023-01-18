package com.moshkovoleg.model;

public enum Permission {
    PRODUCTS_READ("products:read"),
    PRODUCTS_WRITE("products:write"),
    CART_WRITE("cart:write");

    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
