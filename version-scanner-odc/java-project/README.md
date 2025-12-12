# Zafiyetli Java Projesi - Güvenlik Zafiyet Tarama Test Projesi

## Genel Bakış
Bu proje, güvenlik zafiyet tarama araçlarını test etmek için kasıtlı olarak zafiyetli kütüphaneler içeren 3 modüllü bir Maven projesidir.

⚠️ **UYARI**: Bu proje yalnızca test ve eğitim amaçlıdır. Production ortamında KULLANMAYIN!

## Proje Yapısı

```
vulnerable-java-project/
├── pom.xml (Parent POM)
├── module1/ (Logging Service)
│   ├── pom.xml
│   └── src/main/java/com/example/LoggingService.java
├── module2/ (Web Service)
│   ├── pom.xml
│   └── src/main/java/com/example/WebService.java
└── module3/ (Data Service)
    ├── pom.xml
    └── src/main/java/com/example/DataService.java
```

## Modüller ve İçerdikleri Zafiyetler

### Module 1 - Logging Service
**Zafiyetli Kütüphaneler:**
- **Log4j 2.14.1** - CVE-2021-44228 (Log4Shell) - Kritik JNDI Injection zafiyeti
- **Jackson Databind 2.9.8** - CVE-2020-36518 - Deserialization zafiyetleri
- **Jackson Core 2.9.8** - CVE-2019-12384 - Çeşitli güvenlik açıkları

### Module 2 - Web Service
**Zafiyetli Kütüphaneler:**
- **Spring Framework 5.2.0.RELEASE** - CVE-2020-5398 - RFD (Reflected File Download)
- **Commons Collections 3.2.1** - CVE-2015-6420 - Deserialization of Untrusted Data
- **Commons BeanUtils 1.8.3** - CVE-2014-0114 - ClassLoader manipulation

### Module 3 - Data Service
**Zafiyetli Kütüphaneler:**
- **Apache Struts 2.3.20** - CVE-2017-5638 - Remote Code Execution (OGNL injection)
- **MySQL Connector 5.1.42** - CVE-2018-3258 - Authentication bypass
- **Apache HttpClient 4.5.6** - CVE-2020-13956 - Improper certificate validation
- **Commons IO 2.6** - CVE-2021-29425 - Path traversal vulnerability

## Kullanım

### Projeyi Build Etme
```bash
mvn clean install
```

### Güvenlik Zafiyet Taraması

#### OWASP Dependency Check ile:
```bash
mvn org.owasp:dependency-check-maven:check
```

#### Snyk ile:
```bash
snyk test
```

#### GitHub Dependabot ile:
Bu projeyi GitHub'a yükleyin ve Dependabot otomatik olarak zafiyetleri tespit edecektir.

#### Trivy ile:
```bash
trivy fs .
```

#### JFrog Xray veya Sonatype Nexus ile:
Bu araçları CI/CD pipeline'ınıza entegre ederek tarama yapabilirsiniz.

## Beklenen Sonuçlar

Bu projede güvenlik tarama araçları şu tür uyarılar vermelidir:
- **Kritik (Critical)**: Log4Shell, Struts RCE
- **Yüksek (High)**: Deserialization zafiyetleri
- **Orta (Medium)**: Eski kütüphane versiyonları
- **Düşük (Low)**: Bilinen düşük riskli zafiyetler

## Güvenlik Notları

1. **Bu projeyi production ortamında KULLANMAYIN**
2. Bu proje yalnızca:
   - Güvenlik araçlarını test etmek
   - DevSecOps pipeline'larını doğrulamak
   - Eğitim ve demonstrasyon amaçları
   için tasarlanmıştır.

3. Gerçek projelerde:
   - Kütüphaneleri güncel tutun
   - Düzenli zafiyet taraması yapın
   - OWASP Top 10'u takip edin
   - Dependency management yapın

## Çözüm/Düzeltme

Zafiyetleri düzeltmek için her modülün POM dosyasında kütüphane versiyonlarını güncelleyin:

### Güvenli Versiyonlar:
- Log4j: `2.17.1` veya üzeri
- Jackson: `2.13.0` veya üzeri
- Spring Framework: `5.3.20` veya üzeri
- Commons Collections: `3.2.2` veya Commons Collections 4.x
- Struts: `2.5.30` veya üzeri (veya tamamen farklı framework kullanın)
- MySQL Connector: `8.0.28` veya üzeri
- HttpClient: `4.5.13` veya üzeri
- Commons IO: `2.11.0` veya üzeri

## Lisans
Bu proje yalnızca eğitim amaçlıdır. MIT License.

## İletişim
Sorularınız için: DevSecOps Team
