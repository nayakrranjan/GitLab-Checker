package com.metron.controller;

import com.metron.model.Project;
import com.metron.model.ScanRequest;
import com.metron.model.ScanResponse;
import com.metron.model.ScanType;
import com.metron.service.GitLabService;
import com.metron.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;
    private final GitLabService gitLabService;

    // --- Core Scan Endpoints ---

    @PostMapping(value = "/api/v1/scan", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ScanResponse> scanPost(@RequestBody ScanRequest request) {
        ScanResponse response = scanService.scan(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/api/v1/scan", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ScanResponse> scanGet(
            @RequestParam String target,
            @RequestParam(required = false, defaultValue = "AUTO") ScanType type,
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String baseUrl,
            @RequestParam(required = false, defaultValue = "true") Boolean publicOnly
    ) {
        ScanRequest request = new ScanRequest(target, type, token, baseUrl, publicOnly);
        ScanResponse response = scanService.scan(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/api/v1/scan/table", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> scanTable(
            @RequestParam String target,
            @RequestParam(required = false, defaultValue = "AUTO") ScanType type,
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String baseUrl,
            @RequestParam(required = false, defaultValue = "true") Boolean publicOnly
    ) {
        ScanRequest request = new ScanRequest(target, type, token, baseUrl, publicOnly);
        ScanResponse response = scanService.scan(request);
        return ResponseEntity.ok(response.toCliTable());
    }

    @GetMapping(value = "/api/v1/scan/export/json")
    public ResponseEntity<String> exportJson(
            @RequestParam String target,
            @RequestParam(required = false, defaultValue = "AUTO") ScanType type,
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String baseUrl,
            @RequestParam(required = false, defaultValue = "true") Boolean publicOnly
    ) throws IOException {
        ScanRequest request = new ScanRequest(target, type, token, baseUrl, publicOnly);
        ScanResponse response = scanService.scan(request);
        String json = scanService.exportJson(response);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-report-" + target + ".json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(json);
    }

    @GetMapping(value = "/api/v1/scan/export/pdf")
    public ResponseEntity<byte[]> exportPdf(
            @RequestParam String target,
            @RequestParam(required = false, defaultValue = "AUTO") ScanType type,
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String baseUrl,
            @RequestParam(required = false, defaultValue = "true") Boolean publicOnly
    ) throws IOException {
        ScanRequest request = new ScanRequest(target, type, token, baseUrl, publicOnly);
        ScanResponse response = scanService.scan(request);
        byte[] pdfBytes = scanService.exportPdf(response);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-report-" + target + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfBytes);
    }

    // --- GitLab Direct Query Endpoints ---

    @GetMapping("/api/v1/gitlab/users/{username}/projects")
    public List<Project> getUserProjects(@PathVariable String username) {
        return gitLabService.getUserProjects(username);
    }

    @GetMapping("/api/v1/gitlab/groups/{group}/projects")
    public List<Project> getGroupProjects(@PathVariable String group) {
        return gitLabService.getGroupProjects(group);
    }
}
