package com.metron.model;

public record ScanRequest(
        String target,
        ScanType type,
        String token,
        String baseUrl,
        Boolean publicOnly
) {
    public ScanRequest(String target) {
        this(target, ScanType.AUTO, null, null, true);
    }

    public ScanType effectiveType() {
        return type != null ? type : ScanType.AUTO;
    }

    public boolean isPublicOnly() {
        return publicOnly == null || publicOnly;
    }
}
