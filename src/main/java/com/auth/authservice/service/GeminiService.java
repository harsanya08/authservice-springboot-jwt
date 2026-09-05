package com.auth.authservice.service;

import com.auth.authservice.model.SecurityAnalysis;
import com.auth.authservice.model.SecurityEvent;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@Service
public class GeminiService {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SecurityAnalysis analyzeSecurityEvent(SecurityEvent event) {

        String apiKey = System.getenv("GEMINI_API_KEY");

        if (apiKey == null || apiKey.isBlank()) {
            return deterministicFallback(
                    event,
                    "Gemini API key not found. Deterministic security rules were used."
            );
        }

        String prompt = """
                You are an API security analyst.

                Analyze the following API security event:

                IP Address: %s
                Endpoint: %s
                HTTP Method: %s
                Failed Attempts: %d
                Requests Per Minute: %d
                User Role: %s

                Determine:
                1. Risk level: LOW, MEDIUM, or HIGH
                2. Recommendation: ALLOW, REVIEW, or BLOCK
                3. A short explanation of why.

                Return ONLY valid JSON in exactly this format:

                {
                  "riskLevel": "HIGH",
                  "recommendation": "BLOCK",
                  "reason": "Short explanation here"
                }

                Do not use Markdown.
                Do not use code fences.
                Do not include any text before or after the JSON.
                """.formatted(
                event.getIpAddress(),
                event.getEndpoint(),
                event.getMethod(),
                event.getFailedAttempts(),
                event.getRequestsPerMinute(),
                event.getUserRole()
        );

        try {

            String escapedPrompt = prompt
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n");

            String requestBody = """
                    {
                      "contents": [
                        {
                          "parts": [
                            {
                              "text": "%s"
                            }
                          ]
                        }
                      ]
                    }
                    """.formatted(escapedPrompt);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(
                            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"
                    ))
                    .header("x-goog-api-key", apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() < 200 || response.statusCode() >= 300) {

                return deterministicFallback(
                        event,
                        "Gemini temporarily unavailable (HTTP "
                                + response.statusCode()
                                + "). Deterministic security rules were used."
                );
            }

            // Parse Gemini's outer JSON response
            JsonNode root = objectMapper.readTree(response.body());

            JsonNode textNode = root
                    .path("candidates")
                    .path(0)
                    .path("content")
                    .path("parts")
                    .path(0)
                    .path("text");

            if (textNode.isMissingNode()) {

                return deterministicFallback(
                        event,
                        "Gemini response did not contain analysis text. "
                                + "Deterministic security rules were used."
                );
            }

            String aiText = textNode.asText().trim();

            // Remove code fences if Gemini happens to add them
            if (aiText.startsWith("```")) {
                aiText = aiText
                        .replaceFirst("^```json\\s*", "")
                        .replaceFirst("^```\\s*", "")
                        .replaceFirst("\\s*```$", "")
                        .trim();
            }

            // Parse Gemini's JSON analysis
            return objectMapper.readValue(
                    aiText,
                    SecurityAnalysis.class
            );

        } catch (Exception e) {

            return deterministicFallback(
                    event,
                    "Gemini analysis failed. Deterministic security rules were used."
            );
        }
    }

    private SecurityAnalysis deterministicFallback(
            SecurityEvent event,
            String fallbackMessage) {

        SecurityAnalysis analysis = new SecurityAnalysis();

        boolean highRisk =
                event.getFailedAttempts() >= 5
                        || event.getRequestsPerMinute() >= 30
                        || (
                        "USER".equalsIgnoreCase(event.getUserRole())
                                && event.getEndpoint() != null
                                && event.getEndpoint().startsWith("/api/admin")
                );

        if (highRisk) {

            analysis.setRiskLevel("HIGH");
            analysis.setRecommendation("BLOCK");
            analysis.setReason(
                    fallbackMessage
                            + " Suspicious activity detected based on "
                            + "failed attempts, request rate, or unauthorized "
                            + "administrative access."
            );

        } else if (
                event.getFailedAttempts() >= 2
                        || event.getRequestsPerMinute() >= 15
        ) {

            analysis.setRiskLevel("MEDIUM");
            analysis.setRecommendation("REVIEW");
            analysis.setReason(
                    fallbackMessage
                            + " Moderate activity detected; further review "
                            + "is recommended."
            );

        } else {

            analysis.setRiskLevel("LOW");
            analysis.setRecommendation("ALLOW");
            analysis.setReason(
                    fallbackMessage
                            + " No significant suspicious activity detected."
            );
        }

        return analysis;
    }
}