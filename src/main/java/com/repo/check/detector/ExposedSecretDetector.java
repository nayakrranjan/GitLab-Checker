package com.repo.check.detector;

import com.repo.check.client.dto.GitLabTreeItem;
import com.repo.check.model.Risk;
import com.repo.check.model.RiskCategory;
import com.repo.check.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ExposedSecretDetector implements RiskDetector {

    Logger log = LoggerFactory.getLogger(ExposedSecretDetector.class);

    public record SecretPattern(
            String name,
            Pattern pattern,
            Severity severity,
            int groupIndex,
            boolean isSpecific
    ) {
        public SecretPattern(String name, String regex, Severity severity, int groupIndex, boolean isSpecific) {
            this(name, Pattern.compile(regex), severity, groupIndex, isSpecific);
        }
    }

    private static final List<SecretPattern> SECRET_PATTERNS = List.of(
            new SecretPattern(
                    "AWS Access Key ID",
                    "\\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "AWS Secret Access Key",
                    "(?i)aws.{0,20}?(?:secret|key|access).{0,5}['\":=\\s]+([0-9a-zA-Z/+]{40})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "GitLab Personal Access Token",
                    "\\b(glpat-[0-9a-zA-Z_\\-]{20,})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "GitHub Personal Access Token",
                    "\\b((?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "Slack Token",
                    "\\b(xox[baprs]-[0-9a-zA-Z]{10,48})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "Private Key Header",
                    "(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "Google Cloud API Key",
                    "\\b(AIza[0-9A-Za-z_\\-]{35})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "Stripe API Key",
                    "\\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24})\\b",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "Database URI Credentials",
                    "(?:postgres|mysql|mongodb(?:\\+srv)?):\\/\\/[^:\\s]+:([^@\\s]+)@[^:\\s]+",
                    Severity.HIGH,
                    1,
                    true
            ),
            new SecretPattern(
                    "Generic API Key",
                    "(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\\s*[:=]\\s*['\"]([0-9a-zA-Z_\\-]{16,64})['\"]",
                    Severity.MEDIUM,
                    1,
                    false
            ),
            new SecretPattern(
                    "Hardcoded Password",
                    "(?i)(?:password|passwd|pwd)\\s*[:=]\\s*['\"]?([a-zA-Z0-9_.\\-]{2,64})['\"]?",
                    Severity.MEDIUM,
                    1,
                    false
            ),
            new SecretPattern(
                    "Hardcoded Username",
                    "(?i)(?:username|uname)\\s*[:=]\\s*['\"]?([a-zA-Z0-9_.\\-]{2,64})['\"]?",
                    Severity.MEDIUM,
                    1,
                    false
            )
    );

    // Extensions to skip (binary, media, build artifacts, lockfiles)
    private static final Set<String> IGNORED_EXTENSIONS = Set.of(
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot",
            ".mp4", ".mp3", ".wav", ".avi",
            ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
            ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".bin"
    );

    private static final Set<String> IGNORED_FILES = Set.of(
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "gemfile.lock",
            "composer.lock"
    );

    @Override
    public List<Risk> detect(RepositoryScanContext context) {
        List<Risk> risks = new ArrayList<>();

        for (GitLabTreeItem item : context.tree()) {
            if (item.isTree()) {
                continue;
            }

            String pathStr = item.path();
            if (pathStr == null || shouldSkipFile(pathStr)) {
                continue;
            }

            Optional<String> contentOpt = context.getFileContent(pathStr);
            if (contentOpt.isEmpty()) {
                continue;
            }

            String content = contentOpt.get();
            if (content.isBlank()) {
                continue;
            }

            risks.addAll(scanContent(pathStr, content));
        }

        return risks;
    }

    public List<Risk> scanContent(String filePath, String content) {
        List<Risk> risks = new ArrayList<>();
        String[] lines = content.split("\r?\n");

        for (int lineNum = 1; lineNum <= lines.length; lineNum++) {
            String line = lines[lineNum - 1];
            log.info(line);

            // Avoid scanning unreasonably long minified lines
            if (line.length() > 1000) {
                continue;
            }

            boolean specificFound = false;

            for (SecretPattern sp : SECRET_PATTERNS) {
                if (specificFound && !sp.isSpecific()) {
                    continue; // Skip generic checks if a specific credential provider matched
                }

                Matcher matcher = sp.pattern().matcher(line);
                if (matcher.find()) {
                    String matchedSecret = matcher.group(sp.groupIndex());
                    String maskedSecret = maskSecret(matchedSecret);
                    String maskedLineSnippet = line.replace(matchedSecret, maskedSecret).trim();

                    risks.add(new Risk(
                            RiskCategory.EXPOSED_SECRET,
                            "Exposed Secrets",
                            "Detected " + sp.name() + " in file: " + filePath + " at line " + lineNum,
                            sp.severity(),
                            filePath,
                            lineNum,
                            maskedLineSnippet,
                            "Revoke and rotate this " + sp.name() + " immediately. Never commit secrets into source control; use environment variables or a secrets manager."
                    ));

                    if (sp.isSpecific()) {
                        specificFound = true;
                    }
                }
            }
        }

        return risks;
    }

    public static String maskSecret(String secret) {
        if (secret == null || secret.length() <= 6) {
            return "******";
        }

        for (String prefix : List.of("glpat-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk_live_", "rk_live_", "AKIA", "ASIA")) {
            if (secret.startsWith(prefix) && secret.length() > prefix.length() + 4) {
                int keepEnd = Math.min(4, secret.length() - prefix.length());
                int maskCount = secret.length() - prefix.length() - keepEnd;
                return prefix + "*".repeat(maskCount) + secret.substring(secret.length() - keepEnd);
            }
        }

        int keep = Math.min(4, secret.length() / 4);
        int maskedLength = secret.length() - (keep * 2);
        return secret.substring(0, keep) + "*".repeat(maskedLength) + secret.substring(secret.length() - keep);
    }

    private boolean shouldSkipFile(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        for (String ignoredExt : IGNORED_EXTENSIONS) {
            if (lower.endsWith(ignoredExt)) {
                return true;
            }
        }
        String fileName = lower.substring(lower.lastIndexOf('/') + 1);
        return IGNORED_FILES.contains(fileName);
    }
}
