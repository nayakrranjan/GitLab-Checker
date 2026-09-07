package com.metron.detector;

import java.util.Optional;

@FunctionalInterface
public interface FileContentProvider {
    Optional<String> getContent(String filePath);
}
