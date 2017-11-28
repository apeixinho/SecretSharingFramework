package com.secretsharing.commons;

/**
 *
 * @author apeixinho
 */
public enum StatusCode {

    OK("OK"),
    NOK("Not OK"),
    UNKNOWN_ERROR("Unknown error");

    private final String description;

    private StatusCode(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

}
