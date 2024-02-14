package com.ohgiraffers.security.user.model;

public enum OhgiraffersRole {

    USER("USER"),
    ADMIN("ADMIN"),
    ALL("USER,ADMIN");

    private String role;

    OhgiraffersRole(String role){
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String toString() {
        return "OhgiraffersRole{" +
                "role='" + role + '\'' +
                '}';
    }
}
