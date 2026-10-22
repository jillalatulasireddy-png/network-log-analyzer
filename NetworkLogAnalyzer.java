
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class NetworkLogAnalyzer {

    private static final int FAILED_LOGIN_THRESHOLD = 3;
    private static final int HIGH_TRAFFIC_THRESHOLD = 5;

    static class LogEvent {
        LocalDateTime timestamp;
        String protocol;
        String sourceIP;
        String destinationIP;
        int port;
        String status;

        LogEvent(String line) {
            String[] parts = line.trim().split("\\s+");

            if (parts.length != 6) {
                throw new IllegalArgumentException(
                    "Expected 6 fields"
                );
            }

            try {
                timestamp = LocalDateTime.parse(parts[0]);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException(
                    "Invalid timestamp"
                );
            }

            protocol = parts[1].toUpperCase();
            sourceIP = parts[2];
            destinationIP = parts[3];

            try {
                port = Integer.parseInt(parts[4]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                    "Invalid port"
                );
            }

            status = parts[5].toUpperCase();

            if (!protocol.matches("[A-Z0-9_-]+")
                    || !isValidIP(sourceIP)
                    || !isValidIP(destinationIP)
                    || port < 1 || port > 65535
                    || !(status.equals("SUCCESS")
                    || status.equals("FAILED")
                    || status.equals("BLOCKED"))) {
                throw new IllegalArgumentException(
                    "Invalid log field"
                );
            }
        }
    }

    static boolean isValidIP(String ip) {
        // Validate IPv4 addresses.
        String[] parts = ip.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (!part.matches("\\d{1,3}")) {
                return false;
            }

            int value = Integer.parseInt(part);

            if (value > 255) {
                return false;
            }
        }

        return true;
    }

    static class AnalysisResult {
        List<LogEvent> events = new ArrayList<>();
        Map<String, Integer> protocolCounts = new TreeMap<>();
        Map<String, Integer> sourceCounts = new HashMap<>();
        Map<String, Integer> failedCounts = new HashMap<>();
        List<String> alerts = new ArrayList<>();
        int invalidLines = 0;
    }

    static AnalysisResult analyze(String filePath)
            throws IOException {

        AnalysisResult result = new AnalysisResult();

        try (BufferedReader reader = Files.newBufferedReader(
                Paths.get(filePath), StandardCharsets.UTF_8)) {

            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                if (line.trim().isEmpty()
                        || line.trim().startsWith("#")) {
                    continue;
                }

                try {
                    LogEvent event = new LogEvent(line);
                    result.events.add(event);

                    result.protocolCounts.merge(
                        event.protocol, 1, Integer::sum
                    );

                    result.sourceCounts.merge(
                        event.sourceIP, 1, Integer::sum
                    );

                    if (event.status.equals("FAILED")
                            || event.status.equals("BLOCKED")) {
                        result.failedCounts.merge(
                            event.sourceIP, 1, Integer::sum
                        );
                    }

                } catch (IllegalArgumentException e) {
                    result.invalidLines++;
                    System.out.println(
                        "Skipping invalid line " + lineNumber
                        + ": " + e.getMessage()
                    );
                }
            }
        }

        detectSuspiciousActivity(result);
        return result;
    }

    static void detectSuspiciousActivity(
            AnalysisResult result) {

        for (Map.Entry<String, Integer> entry
                : result.failedCounts.entrySet()) {

            if (entry.getValue() >= FAILED_LOGIN_THRESHOLD) {
                result.alerts.add(
                    "REPEATED FAILURES: " + entry.getKey()
                    + " has " + entry.getValue()
                    + " failed/blocked events."
                );
            }
        }

        for (Map.Entry<String, Integer> entry
                : result.sourceCounts.entrySet()) {

            if (entry.getValue() >= HIGH_TRAFFIC_THRESHOLD) {
                result.alerts.add(
                    "HIGH EVENT VOLUME: " + entry.getKey()
                    + " has " + entry.getValue()
                    + " events."
                );
            }
        }

        for (LogEvent event : result.events) {
            // Flag selected ports for review, not as proof of an attack.
            if (event.port == 23 || event.port == 3389
                    || event.port == 4444) {
                result.alerts.add(
                    "PORT REVIEW: " + event.sourceIP
                    + " -> " + event.destinationIP
                    + ":" + event.port
                    + " (" + event.protocol + ")"
                );
            }
        }
    }

    static String buildReport(AnalysisResult result) {
        StringBuilder report = new StringBuilder();

        report.append("====== NETWORK LOG ANALYSIS REPORT ======\n");
        report.append("Total valid events: ")
              .append(result.events.size()).append("\n");
        report.append("Invalid lines skipped: ")
              .append(result.invalidLines).append("\n");

        report.append("\n--- Protocol Statistics ---\n");

        for (Map.Entry<String, Integer> entry
                : result.protocolCounts.entrySet()) {
            report.append(entry.getKey())
                  .append(": ")
                  .append(entry.getValue())
                  .append("\n");
        }

        report.append("\n--- Top Source IP Addresses ---\n");

        List<Map.Entry<String, Integer>> sources =
            new ArrayList<>(result.sourceCounts.entrySet());

        sources.sort(
            Comparator.<Map.Entry<String, Integer>>
                comparingInt(Map.Entry::getValue)
                .reversed()
                .thenComparing(Map.Entry::getKey)
        );

        for (int i = 0; i < Math.min(5, sources.size()); i++) {
            Map.Entry<String, Integer> entry = sources.get(i);

            report.append(entry.getKey())
                  .append(" -> ")
                  .append(entry.getValue())
                  .append(" events\n");
        }

        report.append("\n--- Suspicious Activity Alerts ---\n");

        if (result.alerts.isEmpty()) {
            report.append("No configured rules were triggered.\n");
        } else {
            for (String alert : result.alerts) {
                report.append("[REVIEW] ")
                      .append(alert).append("\n");
            }
        }

        report.append(
            "\nNote: Alerts indicate patterns requiring investigation; "
            + "they do not prove malicious activity.\n"
        );

        return report.toString();
    }

    static void saveReport(String report, String outputPath)
            throws IOException {

        try (BufferedWriter writer = Files.newBufferedWriter(
                Paths.get(outputPath), StandardCharsets.UTF_8)) {
            writer.write(report);
        }
    }

    public static void main(String[] args) {
        String inputFile = args.length >= 1
            ? args[0] : "network.log";

        String outputFile = args.length >= 2
            ? args[1] : "analysis-report.txt";

        try {
            AnalysisResult result = analyze(inputFile);
            String report = buildReport(result);

            System.out.println(report);
            saveReport(report, outputFile);

            System.out.println(
                "Report saved to: " + outputFile
            );

        } catch (IOException e) {
            System.out.println(
                "File error: " + e.getMessage()
            );
        }
    }
}
