package com.example;

import org.springframework.web.client.RestTemplate;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.beanutils.BeanUtils;

/**
 * Module 2 - Web Service
 * Bu modül Spring Framework ve Commons Collections zafiyetlerini içerir
 */
public class WebService {
    
    private RestTemplate restTemplate = new RestTemplate();
    
    public String fetchData(String url) {
        try {
            // ZAFİYET: Eski Spring sürümü - çeşitli zafiyetler
            return restTemplate.getForObject(url, String.class);
        } catch (Exception e) {
            System.err.println("Error fetching data: " + e.getMessage());
            return null;
        }
    }
    
    public Object processUntrustedData(Object data) {
        try {
            // ZAFİYET: Commons Collections deserialization
            InvokerTransformer transformer = new InvokerTransformer("toString", null, null);
            return transformer.transform(data);
        } catch (Exception e) {
            System.err.println("Error processing data: " + e.getMessage());
            return null;
        }
    }
    
    public void copyProperties(Object source, Object target) {
        try {
            // ZAFİYET: Commons BeanUtils - class loader manipulation
            BeanUtils.copyProperties(target, source);
        } catch (Exception e) {
            System.err.println("Error copying properties: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        WebService service = new WebService();
        System.out.println("Web Service - Module 2 çalışıyor");
    }
}
