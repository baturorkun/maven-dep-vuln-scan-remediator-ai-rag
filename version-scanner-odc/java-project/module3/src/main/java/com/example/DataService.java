package com.example;

import org.apache.struts2.ServletActionContext;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * Module 3 - Data Service
 * Bu modül Apache Struts, MySQL Connector ve HttpClient zafiyetlerini içerir
 */
public class DataService {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    
    public Connection getDatabaseConnection(String username, String password) {
        try {
            // ZAFİYET: Eski MySQL Connector versiyonu
            Class.forName("com.mysql.jdbc.Driver");
            return DriverManager.getConnection(DB_URL, username, password);
        } catch (Exception e) {
            System.err.println("Database connection error: " + e.getMessage());
            return null;
        }
    }
    
    public String fetchRemoteData(String url) {
        try {
            // ZAFİYET: Eski Apache HttpClient versiyonu
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            // Güvenlik açığı: SSL sertifika doğrulaması yok
            return "Data fetched from: " + url;
        } catch (Exception e) {
            System.err.println("Error fetching remote data: " + e.getMessage());
            return null;
        }
    }
    
    public void processFile(String filePath) {
        try {
            // ZAFİYET: Commons IO - path traversal zafiyeti
            File file = new File(filePath);
            String content = FileUtils.readFileToString(file, "UTF-8");
            System.out.println("File processed: " + filePath);
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }
    
    public String executeStrutsAction(String actionName) {
        try {
            // ZAFİYET: Apache Struts - OGNL injection (CVE-2017-5638)
            // Bu kod örnek amaçlıdır ve gerçek Struts action kullanımını simüle eder
            return "Action executed: " + actionName;
        } catch (Exception e) {
            System.err.println("Error executing action: " + e.getMessage());
            return null;
        }
    }
    
    public static void main(String[] args) {
        DataService service = new DataService();
        System.out.println("Data Service - Module 3 çalışıyor");
        service.processFile("test.txt");
    }
}
