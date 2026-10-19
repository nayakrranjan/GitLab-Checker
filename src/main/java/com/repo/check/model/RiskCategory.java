package com.repo.check.model;

public enum RiskCategory {
    SENSITIVE_FILE("Sensitive Files"),
    EXPOSED_SECRET("Exposed Secrets"),
    MISSING_METADATA("Missing Metadata");

    private final String displayName;

    RiskCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
