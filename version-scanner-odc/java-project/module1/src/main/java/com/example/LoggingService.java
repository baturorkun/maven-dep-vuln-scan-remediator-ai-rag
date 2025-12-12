package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Module 1 - Logging Service
 * Bu modül Log4Shell (CVE-2021-44228) ve Jackson zafiyetlerini içerir
 */
public class LoggingService {
    
    private static final Logger logger = LogManager.getLogger(LoggingService.class);
    private ObjectMapper objectMapper = new ObjectMapper();
    
    public void logMessage(String message) {
        // ZAFİYET: Log4Shell - JNDI Lookup zafiyeti
        logger.info("User input: {}", message);
    }
    
    public Object deserializeJson(String json) {
        try {
            // ZAFİYET: Jackson deserialization zafiyeti
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            logger.error("Deserialization error", e);
            return null;
        }
    }
    
    public static void main(String[] args) {
        LoggingService service = new LoggingService();
        service.logMessage("Test message");
        System.out.println("Logging Service - Module 1 çalışıyor");
    }
}
