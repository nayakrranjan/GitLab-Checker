package com.repo.check.service;

import com.repo.check.model.ProjectScanResult;
import com.repo.check.model.Risk;
import com.repo.check.model.ScanResponse;
import com.repo.check.model.Severity;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Component
public class PdfReportGenerator {

    /**
     * Generates a valid standard PDF 1.4 document from scan results without requiring external native libraries.
     */
    public byte[] generatePdf(ScanResponse response) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        List<Long> xrefOffsets = new ArrayList<>();

        // 1. PDF Header
        write(baos, "%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n");

        // We will generate pages based on content length
        List<String> pageStreams = buildPageStreams(response);
        int pageCount = pageStreams.size();

        // Object 1: Catalog
        xrefOffsets.add((long) baos.size());
        write(baos, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        // Object 2: Pages
        xrefOffsets.add((long) baos.size());
        StringBuilder pagesObj = new StringBuilder("2 0 obj\n<< /Type /Pages /Kids [");
        for (int i = 0; i < pageCount; i++) {
            pagesObj.append(3 + i * 2).append(" 0 R ");
        }
        pagesObj.append("] /Count ").append(pageCount).append(" >>\nendobj\n");
        write(baos, pagesObj.toString());

        // For each page:
        // Page Object: 3 + i*2
        // Stream Object: 4 + i*2
        int fontObjIndex = 3 + pageCount * 2;
        int boldFontObjIndex = fontObjIndex + 1;

        for (int i = 0; i < pageCount; i++) {
            int pageObjIndex = 3 + i * 2;
            int streamObjIndex = pageObjIndex + 1;
            String streamContent = pageStreams.get(i);
            byte[] streamBytes = streamContent.getBytes(StandardCharsets.ISO_8859_1);

            // Page Object
            xrefOffsets.add((long) baos.size());
            String pageStr = String.format(
                    "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
                            "/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> " +
                            "/Contents %d 0 R >>\nendobj\n",
                    pageObjIndex, fontObjIndex, boldFontObjIndex, streamObjIndex
            );
            write(baos, pageStr);

            // Stream Object
            xrefOffsets.add((long) baos.size());
            write(baos, String.format("%d 0 obj\n<< /Length %d >>\nstream\n", streamObjIndex, streamBytes.length));
            baos.write(streamBytes);
            write(baos, "\nendstream\nendobj\n");
        }

        // Font F1: Helvetica (Regular)
        xrefOffsets.add((long) baos.size());
        write(baos, fontObjIndex + " 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

        // Font F2: Helvetica-Bold
        xrefOffsets.add((long) baos.size());
        write(baos, boldFontObjIndex + " 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n");

        // Cross-reference table
        long xrefStart = baos.size();
        int totalObjects = xrefOffsets.size() + 1;
        write(baos, "xref\n0 " + totalObjects + "\n0000000000 65535 f \n");
        for (Long offset : xrefOffsets) {
            write(baos, String.format("%010d 00000 n \n", offset));
        }

        // Trailer
        write(baos, "trailer\n<< /Size " + totalObjects + " /Root 1 0 R >>\nstartxref\n" + xrefStart + "\n%%EOF\n");

        return baos.toByteArray();
    }

    private List<String> buildPageStreams(ScanResponse response) {
        List<String> pages = new ArrayList<>();
        StringBuilder ps = new StringBuilder();

        // Page 1 Header
        ps.append("q\n");
        // Header background banner (Dark Slate)
        ps.append("0.12 0.16 0.23 rg 36 710 540 50 re f\n");
        // Title
        ps.append("BT /F2 18 Tf 1 1 1 rg 50 730 Td (GitLab Public Repository Risk Scanner) Tj ET\n");
        ps.append("BT /F1 10 Tf 0.8 0.85 0.9 rg 50 717 Td (Automated Security and Misconfiguration Audit Report) Tj ET\n");

        // Target Info Box
        ps.append("0.95 0.96 0.98 rg 36 630 540 65 re f\n");
        ps.append("0.8 0.82 0.85 RG 1 w 36 630 540 65 re S\n");

        ps.append("BT /F2 10 Tf 0.2 0.2 0.2 rg 50 675 Td (Target: ) Tj /F1 10 Tf (")
                .append(escape(response.target())).append(" [").append(response.targetType()).append("]) Tj ET\n");
        ps.append("BT /F2 10 Tf 0.2 0.2 0.2 rg 50 658 Td (Scanned At: ) Tj /F1 10 Tf (")
                .append(escape(response.scannedAt())).append(") Tj ET\n");
        ps.append("BT /F2 10 Tf 0.2 0.2 0.2 rg 50 641 Td (Summary: ) Tj /F1 10 Tf (Repositories: ")
                .append(response.totalProjectsScanned())
                .append(" | Total Risks: ").append(response.totalRisksFound())
                .append(" | High: ").append(response.highSeverityCount())
                .append(" | Medium: ").append(response.mediumSeverityCount())
                .append(" | Low: ").append(response.lowSeverityCount())
                .append(") Tj ET\n");

        // Table Header
        int y = 595;
        ps.append("0.2 0.25 0.35 rg 36 ").append(y).append(" 540 22 re f\n");
        ps.append("BT /F2 10 Tf 1 1 1 rg 45 ").append(y + 6).append(" Td (Project Name) Tj ET\n");
        ps.append("BT /F2 10 Tf 1 1 1 rg 190 ").append(y + 6).append(" Td (Issue / Category) Tj ET\n");
        ps.append("BT /F2 10 Tf 1 1 1 rg 380 ").append(y + 6).append(" Td (Severity) Tj ET\n");
        ps.append("BT /F2 10 Tf 1 1 1 rg 445 ").append(y + 6).append(" Td (File Location) Tj ET\n");

        y -= 20;

        List<ProjectScanResult> results = response.results() != null ? response.results() : List.of();
        boolean anyFinding = false;

        for (ProjectScanResult project : results) {
            if (project.risks().isEmpty()) {
                if (y < 60) {
                    pages.add(ps.toString());
                    ps = new StringBuilder("q\n");
                    y = 740;
                }
                ps.append("0.96 0.96 0.96 rg 36 ").append(y).append(" 540 18 re f\n");
                ps.append("BT /F1 9 Tf 0.2 0.2 0.2 rg 45 ").append(y + 5).append(" Td (")
                        .append(escape(project.projectName())).append(") Tj ET\n");
                ps.append("BT /F1 9 Tf 0.1 0.6 0.2 rg 190 ").append(y + 5).append(" Td (No risks detected - Clean) Tj ET\n");
                ps.append("BT /F1 9 Tf 0.4 0.4 0.4 rg 380 ").append(y + 5).append(" Td (None) Tj ET\n");
                ps.append("BT /F1 9 Tf 0.5 0.5 0.5 rg 445 ").append(y + 5).append(" Td (-) Tj ET\n");
                y -= 22;
            } else {
                anyFinding = true;
                for (Risk risk : project.risks()) {
                    if (y < 60) {
                        pages.add(ps.toString());
                        ps = new StringBuilder("q\n");
                        y = 740;
                    }

                    // Background highlight
                    ps.append("0.98 0.98 0.99 rg 36 ").append(y).append(" 540 18 re f\n");

                    // Project name
                    String projName = truncate(project.projectName(), 22);
                    ps.append("BT /F1 9 Tf 0.1 0.1 0.1 rg 45 ").append(y + 5).append(" Td (")
                            .append(escape(projName)).append(") Tj ET\n");

                    // Issue
                    String issueStr = truncate(risk.issue() != null ? risk.issue() : risk.category().getDisplayName(), 28);
                    ps.append("BT /F1 9 Tf 0.2 0.2 0.2 rg 190 ").append(y + 5).append(" Td (")
                            .append(escape(issueStr)).append(") Tj ET\n");

                    // Severity with color
                    if (risk.severity() == Severity.HIGH) {
                        ps.append("BT /F2 9 Tf 0.85 0.15 0.15 rg 380 ").append(y + 5).append(" Td (HIGH) Tj ET\n");
                    } else if (risk.severity() == Severity.MEDIUM) {
                        ps.append("BT /F2 9 Tf 0.85 0.55 0.05 rg 380 ").append(y + 5).append(" Td (MEDIUM) Tj ET\n");
                    } else {
                        ps.append("BT /F2 9 Tf 0.2 0.45 0.85 rg 380 ").append(y + 5).append(" Td (LOW) Tj ET\n");
                    }

                    // File
                    String fileStr = truncate(risk.file() != null ? risk.file() : "Repository Root", 20);
                    ps.append("BT /F1 9 Tf 0.3 0.3 0.3 rg 445 ").append(y + 5).append(" Td (")
                            .append(escape(fileStr)).append(") Tj ET\n");

                    y -= 22;
                }
            }
        }

        pages.add(ps.toString());
        return pages;
    }

    private void write(ByteArrayOutputStream baos, String str) throws IOException {
        baos.write(str.getBytes(StandardCharsets.ISO_8859_1));
    }

    private String escape(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replaceAll("[^\\x20-\\x7E]", "");
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return "-";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}
