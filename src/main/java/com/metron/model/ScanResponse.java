package com.metron.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public record ScanResponse(
        String target,
        ScanType targetType,
        String scannedAt,
        int totalProjectsScanned,
        long totalRisksFound,
        long highSeverityCount,
        long mediumSeverityCount,
        long lowSeverityCount,
        List<ProjectScanResult> results
) {
    public ScanResponse(String target, ScanType targetType, List<ProjectScanResult> results) {
        this(
                target,
                targetType,
                Instant.now().toString(),
                results != null ? results.size() : 0,
                results != null ? results.stream().mapToLong(r -> r.risks().size()).sum() : 0,
                results != null ? results.stream().mapToLong(ProjectScanResult::highRiskCount).sum() : 0,
                results != null ? results.stream().mapToLong(ProjectScanResult::mediumRiskCount).sum() : 0,
                results != null ? results.stream().mapToLong(ProjectScanResult::lowRiskCount).sum() : 0,
                results != null ? results : List.of()
        );
    }

    /**
     * Formats the scan results into the standard CLI table format requested in the specification:
     * Project Name | Issue | Severity
     */
    public String toCliTable() {
        StringBuilder sb = new StringBuilder();
        sb.append(System.lineSeparator());
        sb.append("==========================================================================================").append(System.lineSeparator());
        sb.append(String.format(" GitLab Repository Risk Scan Report - Target: %s (%s)%n", target, targetType));
        sb.append(String.format(" Scanned At: %s | Projects: %d | Total Risks: %d (High: %d, Med: %d, Low: %d)%n",
                scannedAt, totalProjectsScanned, totalRisksFound, highSeverityCount, mediumSeverityCount, lowSeverityCount));
        sb.append("==========================================================================================").append(System.lineSeparator());

        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"Project Name", "Issue", "Severity"});

        boolean hasAnyRisks = false;
        if (results != null) {
            for (ProjectScanResult project : results) {
                if (project.risks().isEmpty()) {
                    rows.add(new String[]{project.projectName(), "No issues detected", "None"});
                } else {
                    hasAnyRisks = true;
                    for (Risk risk : project.risks()) {
                        String issueName = risk.issue() != null ? risk.issue() : risk.category().getDisplayName();
                        rows.add(new String[]{
                                project.projectName(),
                                issueName,
                                risk.severity() != null ? risk.severity().getDisplayName() : "Unknown"
                        });
                    }
                }
            }
        }

        int col1Width = 14;
        int col2Width = 18;
        int col3Width = 10;

        for (String[] row : rows) {
            col1Width = Math.max(col1Width, row[0].length());
            col2Width = Math.max(col2Width, row[1].length());
            col3Width = Math.max(col3Width, row[2].length());
        }

        col1Width += 2;
        col2Width += 2;
        col3Width += 2;

        String horizontalBorder = "+" + "-".repeat(col1Width) + "+" + "-".repeat(col2Width) + "+" + "-".repeat(col3Width) + "+";

        sb.append(horizontalBorder).append(System.lineSeparator());
        sb.append(String.format("| %-" + (col1Width - 2) + "s | %-" + (col2Width - 2) + "s | %-" + (col3Width - 2) + "s |%n",
                rows.getFirst()[0], rows.getFirst()[1], rows.getFirst()[2]));
        sb.append(horizontalBorder).append(System.lineSeparator());

        for (int i = 1; i < rows.size(); i++) {
            String[] row = rows.get(i);
            sb.append(String.format("| %-" + (col1Width - 2) + "s | %-" + (col2Width - 2) + "s | %-" + (col3Width - 2) + "s |%n",
                    row[0], row[1], row[2]));
        }
        sb.append(horizontalBorder).append(System.lineSeparator());

        // Also add detailed breakdown if any risks were found
        if (hasAnyRisks) {
            sb.append(System.lineSeparator());
            sb.append("--- Detailed Findings ---").append(System.lineSeparator());
            for (ProjectScanResult project : results) {
                if (!project.risks().isEmpty()) {
                    sb.append(String.format("Project: %s (%s)%n", project.projectName(), project.projectPath()));
                    for (Risk risk : project.risks()) {
                        sb.append(String.format("  [%s] %s%n", risk.severity(), risk.description()));
                        if (risk.file() != null) {
                            sb.append(String.format("    File: %s%s%n", risk.file(), risk.line() != null ? ":" + risk.line() : ""));
                        }
                        if (risk.snippet() != null && !risk.snippet().isBlank()) {
                            sb.append(String.format("    Snippet: %s%n", risk.snippet()));
                        }
                        if (risk.remediation() != null && !risk.remediation().isBlank()) {
                            sb.append(String.format("    Remediation: %s%n", risk.remediation()));
                        }
                    }
                    sb.append(System.lineSeparator());
                }
            }
        }

        return sb.toString();
    }
}
