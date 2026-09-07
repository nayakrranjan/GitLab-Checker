package com.metron.service;

import com.metron.client.dto.GitLabTreeItem;
import com.metron.detector.FileContentProvider;
import com.metron.detector.RepositoryScanContext;
import com.metron.detector.RiskDetector;
import com.metron.model.Project;
import com.metron.model.ProjectScanResult;
import com.metron.model.Risk;
import com.metron.model.ScanRequest;
import com.metron.model.ScanResponse;
import com.metron.util.JsonWriter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final GitLabService gitLabService;
    private final List<RiskDetector> detectors;
    private final PdfReportGenerator pdfReportGenerator;

    public ScanResponse scan(String usernameOrGroup) {
        return scan(new ScanRequest(usernameOrGroup));
    }

    public ScanResponse scan(ScanRequest request) {
        log.info("Starting scan for target='{}', type='{}', baseUrl='{}'",
                request.target(), request.effectiveType(), request.baseUrl());

        List<Project> projects = gitLabService.resolveProjects(request);
        log.info("Found {} projects to scan for target '{}'", projects.size(), request.target());

        List<ProjectScanResult> projectResults = new ArrayList<>();

        for (Project project : projects) {
            log.info("Scanning project: {} (ID: {})", project.name(), project.id());
            ProjectScanResult result = scanProject(project, request.baseUrl(), request.token());
            projectResults.add(result);
        }

        ScanResponse response = new ScanResponse(
                request.target(),
                request.effectiveType(),
                projectResults
        );

        log.info("Completed scan for '{}': {} projects, {} total risks (High: {}, Med: {}, Low: {})",
                request.target(),
                response.totalProjectsScanned(),
                response.totalRisksFound(),
                response.highSeverityCount(),
                response.mediumSeverityCount(),
                response.lowSeverityCount());

        return response;
    }

    private ProjectScanResult scanProject(Project project, String baseUrl, String token) {
        List<GitLabTreeItem> tree = gitLabService.getRepositoryTree(project, baseUrl, token);
        FileContentProvider contentProvider = gitLabService.getFileContentProvider(project, baseUrl, token);
        RepositoryScanContext context = new RepositoryScanContext(project, tree, contentProvider);

        List<Risk> allRisks = new ArrayList<>();
        for (RiskDetector detector : detectors) {
            try {
                List<Risk> detectedRisks = detector.detect(context);
                if (detectedRisks != null) {
                    allRisks.addAll(detectedRisks);
                }
            } catch (Exception e) {
                log.error("Detector {} failed on project {}: {}", detector.getClass().getSimpleName(), project.name(), e.getMessage());
            }
        }

        return new ProjectScanResult(project, allRisks);
    }

    public byte[] exportPdf(ScanResponse response) throws IOException {
        return pdfReportGenerator.generatePdf(response);
    }

    public String exportJson(ScanResponse response) {
        return JsonWriter.toJson(response);
    }
}
