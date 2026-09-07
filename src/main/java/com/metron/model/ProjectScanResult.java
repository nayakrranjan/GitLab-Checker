package com.metron.model;

import java.util.List;

public record ProjectScanResult(
        Long projectId,
        String projectName,
        String projectPath,
        String webUrl,
        String visibility,
        List<Risk> risks
) {
    public ProjectScanResult(Project project, List<Risk> risks) {
        this(
                project.id(),
                project.name(),
                project.pathWithNamespace() != null ? project.pathWithNamespace() : project.path(),
                project.webUrl(),
                project.visibility(),
                risks != null ? risks : List.of()
        );
    }

    public long highRiskCount() {
        return risks.stream().filter(r -> r.severity() == Severity.HIGH).count();
    }

    public long mediumRiskCount() {
        return risks.stream().filter(r -> r.severity() == Severity.MEDIUM).count();
    }

    public long lowRiskCount() {
        return risks.stream().filter(r -> r.severity() == Severity.LOW).count();
    }

    public boolean hasRisks() {
        return !risks.isEmpty();
    }
}
