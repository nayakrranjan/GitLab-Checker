package com.metron.model;

public record Risk(
        RiskCategory category,
        String issue,
        String description,
        Severity severity,
        String file,
        Integer line,
        String snippet,
        String remediation
) {
    public Risk(RiskCategory category, String issue, String description, Severity severity, String file) {
        this(category, issue, description, severity, file, null, null, null);
    }

    public Risk(RiskCategory category, String description, Severity severity, String file) {
        this(category, category != null ? category.getDisplayName() : "Unknown Issue", description, severity, file, null, null, null);
    }
}