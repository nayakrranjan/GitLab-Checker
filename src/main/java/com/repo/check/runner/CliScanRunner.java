package com.repo.check.runner;

import com.repo.check.model.ScanRequest;
import com.repo.check.model.ScanResponse;
import com.repo.check.model.ScanType;
import com.repo.check.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;

@Component
@RequiredArgsConstructor
public class CliScanRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(CliScanRunner.class);

    private final ScanService scanService;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        String target = null;
        if (args.containsOption("scan.target")) {
            target = args.getOptionValues("scan.target").getFirst();
        } else if (args.containsOption("target")) {
            target = args.getOptionValues("target").getFirst();
        }

        if (target == null || target.isBlank()) {
            return;
        }

        log.info("CLI Scan initiated for target: {}", target);

        ScanType type = ScanType.AUTO;
        if (args.containsOption("scan.type")) {
            try {
                type = ScanType.valueOf(args.getOptionValues("scan.type").getFirst().toUpperCase());
            } catch (Exception ignored) {}
        } else if (args.containsOption("type")) {
            try {
                type = ScanType.valueOf(args.getOptionValues("type").getFirst().toUpperCase());
            } catch (Exception ignored) {}
        }

        String token = null;
        if (args.containsOption("token")) {
            token = args.getOptionValues("token").getFirst();
        } else if (args.containsOption("scan.token")) {
            token = args.getOptionValues("scan.token").getFirst();
        }

        String baseUrl = null;
        if (args.containsOption("baseUrl")) {
            baseUrl = args.getOptionValues("baseUrl").getFirst();
        } else if (args.containsOption("scan.baseUrl")) {
            baseUrl = args.getOptionValues("scan.baseUrl").getFirst();
        }

        boolean publicOnly = true;
        if (args.containsOption("publicOnly")) {
            publicOnly = Boolean.parseBoolean(args.getOptionValues("publicOnly").getFirst());
        }

        ScanRequest request = new ScanRequest(target, type, token, baseUrl, publicOnly);
        ScanResponse response = scanService.scan(request);

        // Print CLI table to standard out
        System.out.println(response.toCliTable());

        if (args.containsOption("export.json")) {
            String jsonPath = args.getOptionValues("export.json").getFirst();
            String json = scanService.exportJson(response);
            Files.writeString(new File(jsonPath).toPath(), json);
            System.out.println("JSON report exported to: " + jsonPath);
        }

        if (args.containsOption("export.pdf")) {
            String pdfPath = args.getOptionValues("export.pdf").getFirst();
            byte[] pdfBytes = scanService.exportPdf(response);
            try (FileOutputStream fos = new FileOutputStream(pdfPath)) {
                fos.write(pdfBytes);
            }
            System.out.println("PDF report exported to: " + pdfPath);
        }
    }
}
