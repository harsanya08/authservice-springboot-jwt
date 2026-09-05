package com.auth.authservice.controller;

import com.auth.authservice.model.SecurityAnalysis;
import com.auth.authservice.model.SecurityEvent;
import com.auth.authservice.service.GeminiService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/security")
public class SecurityController {

    private final GeminiService geminiService;

    public SecurityController(GeminiService geminiService) {
        this.geminiService = geminiService;
    }

    @PostMapping("/analyze")
    public SecurityAnalysis analyze(@RequestBody SecurityEvent event) {

        return geminiService.analyzeSecurityEvent(event);
    }
}