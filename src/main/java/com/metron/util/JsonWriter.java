package com.metron.util;

import com.metron.model.ProjectScanResult;
import com.metron.model.Risk;
import com.metron.model.ScanResponse;

public class JsonWriter {

    public static String toJson(ScanResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"target\": ").append(quote(response.target())).append(",\n");
        sb.append("  \"targetType\": ").append(quote(response.targetType() != null ? response.targetType().name() : "AUTO")).append(",\n");
        sb.append("  \"scannedAt\": ").append(quote(response.scannedAt())).append(",\n");
        sb.append("  \"totalProjectsScanned\": ").append(response.totalProjectsScanned()).append(",\n");
        sb.append("  \"totalRisksFound\": ").append(response.totalRisksFound()).append(",\n");
        sb.append("  \"highSeverityCount\": ").append(response.highSeverityCount()).append(",\n");
        sb.append("  \"mediumSeverityCount\": ").append(response.mediumSeverityCount()).append(",\n");
        sb.append("  \"lowSeverityCount\": ").append(response.lowSeverityCount()).append(",\n");
        sb.append("  \"results\": [\n");

        if (response.results() != null) {
            for (int i = 0; i < response.results().size(); i++) {
                ProjectScanResult pr = response.results().get(i);
                sb.append("    {\n");
                sb.append("      \"projectId\": ").append(pr.projectId()).append(",\n");
                sb.append("      \"projectName\": ").append(quote(pr.projectName())).append(",\n");
                sb.append("      \"projectPath\": ").append(quote(pr.projectPath())).append(",\n");
                sb.append("      \"webUrl\": ").append(quote(pr.webUrl())).append(",\n");
                sb.append("      \"visibility\": ").append(quote(pr.visibility())).append(",\n");
                sb.append("      \"risks\": [\n");

                if (pr.risks() != null) {
                    for (int j = 0; j < pr.risks().size(); j++) {
                        Risk r = pr.risks().get(j);
                        sb.append("        {\n");
                        sb.append("          \"category\": ").append(quote(r.category() != null ? r.category().name() : null)).append(",\n");
                        sb.append("          \"issue\": ").append(quote(r.issue())).append(",\n");
                        sb.append("          \"description\": ").append(quote(r.description())).append(",\n");
                        sb.append("          \"severity\": ").append(quote(r.severity() != null ? r.severity().name() : null)).append(",\n");
                        sb.append("          \"file\": ").append(quote(r.file())).append(",\n");
                        sb.append("          \"line\": ").append(r.line() != null ? r.line().toString() : "null").append(",\n");
                        sb.append("          \"snippet\": ").append(quote(r.snippet())).append(",\n");
                        sb.append("          \"remediation\": ").append(quote(r.remediation())).append("\n");
                        sb.append("        }").append(j < pr.risks().size() - 1 ? "," : "").append("\n");
                    }
                }
                sb.append("      ]\n");
                sb.append("    }").append(i < response.results().size() - 1 ? "," : "").append("\n");
            }
        }
        sb.append("  ]\n");
        sb.append("}");
        return sb.toString();
    }

    private static String quote(String val) {
        if (val == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (char c : val.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
