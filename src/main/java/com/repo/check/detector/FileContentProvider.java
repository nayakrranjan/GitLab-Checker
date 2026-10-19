package com.repo.check.detector;

import java.util.Optional;

@FunctionalInterface
public interface FileContentProvider {
    Optional<String> getContent(String filePath);
}
