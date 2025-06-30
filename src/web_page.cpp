#include "web_page.h"
#include "config.h"
#include "networking_tools.h"
#include <ESPAsyncWebServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <Arduino.h>
#include <LittleFS.h>
#include "esp_task_wdt.h"

AsyncWebServer server(80);

/*
    !!!DISCLAIMER!!!
    I know that this isnt fully optimised so feel free to change any of this
*/

bool wifi_busy = false;
bool pending_update = false;
unsigned long start_update = 0;
bool update_in_progress = false;
bool scan_complete = false;
bool isOverclockOn = false;  // global variable to track state
bool scanInProgress = false;
int currentHostIndex = 0;
std::vector<HostService> scanResults;
std::vector<String> vulnResults;
TaskHandle_t scanTaskHandle = nullptr;

// Task handles
TaskHandle_t hostScanTaskHandle = NULL;
TaskHandle_t beaconSpamTaskHandle = NULL;
TaskHandle_t portScannerTaskHandle = NULL;

void hostScanTask(void* parameter) {
    scan_hosts_ips();  // run host discovery

    // After host discovery, run MAC extraction WITHOUT HTTP request object
    mac_from_arp();

    // Updating channel
    get_channel();

    update_in_progress = false;
    scan_complete = true;
    hostScanTaskHandle = NULL;

    vTaskDelete(NULL);
}

void beacon_spam_task(void* parameter) {
    for (int i = 0; i < 5; i++) {
        beacon_spam();  // send one full round of beacon frames
        vTaskDelay(1000 / portTICK_PERIOD_MS);  // wait 1 second between rounds
    }
    beaconSpamTaskHandle = NULL;
    vTaskDelete(NULL);
}

void port_scanning_task(void* parameter) {
    for (size_t i = 0; i < hosts.size(); i++) {
        port_scanner(hosts[i]);
    }
    vTaskDelay(3000 / portTICK_PERIOD_MS);  // wait 3 second between rounds
    portScannerTaskHandle = NULL;
    vTaskDelete(NULL);
}

void serviceScanTask(void *parameter) {
    scanInProgress = true;
    scanResults.clear();
    currentHostIndex = 0;
    
    for (size_t i = 0; i < hosts.size(); i++) {
        currentHostIndex = i;
        Serial.printf("Scanning host %d/%d: %s\n", i + 1, hosts.size(), hosts[i].toString().c_str());
        IPAddress target = hosts[i];
        
        String result = version_scanner(target);

        String os = detectOS(target);
        
        HostService service;
        service.ip = target;
        service.service = result + ", detected OS: " + os;
        scanResults.push_back(service);
        
        // Critical: Reset watchdog regularly
        esp_task_wdt_reset();
        
        // Small delay between hosts
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
    
    scanInProgress = false;
    vTaskDelete(nullptr);
}

void vuln_scanner_task(void *parameter) {
    scanInProgress = true;
    currentHostIndex = 0;
    vulnResults.clear(); // Clear results at start
    
    // Make local copy of hosts to avoid concurrency issues
    std::vector<IPAddress> targets;
    for (const auto& host : discovered_hosts) {
        targets.push_back(host.ip);
    }

    for (int i = 0; i < targets.size(); i++) {
        currentHostIndex = i;
        IPAddress host = targets[i];
        
        Serial.printf("Scanning host %d/%d: %s\n", 
                     i + 1, targets.size(), host.toString().c_str());
        
        String result = vuln_scanner(host);
        String formattedResult = host.toString() + " - " + 
                               (result.isEmpty() ? "No vulnerabilities found" : result);
        
        vulnResults.push_back(formattedResult);

        // Maintenance
        esp_task_wdt_reset();
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    scanInProgress = false;
    Serial.println("Vulnerability scanning complete.");
    vTaskDelete(nullptr);
}

void SSHBruteforce_task(void *parameter) {
    scanInProgress = true;
    currentHostIndex = 0;
    SSHBruteforce_results.clear(); // Clear results at start

    // Make local copy of hosts to avoid concurrency issues
    std::vector<IPAddress> targets;
    for (const auto& host : discovered_hosts) {
        targets.push_back(host.ip);
    }

    for (int i = 0; i < targets.size(); i++) {
        currentHostIndex = i;
        IPAddress host = targets[i];
        
        Serial.printf("Bruteforcing SSH on host %d/%d: %s\n", 
                     i + 1, targets.size(), host.toString().c_str());
        
        SSHBruteforce(host);

        // Maintenance
        esp_task_wdt_reset();
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    scanInProgress = false;
    Serial.println("SSH Bruteforce complete.");
    vTaskDelete(nullptr);
}

void FTPBruteforce_task(void *parameter) {
    scanInProgress = true;
    currentHostIndex = 0;
    FTPBruteforce_results.clear(); // Clear results at start

    // Make local copy of hosts to avoid concurrency issues
    std::vector<IPAddress> targets;
    for (const auto& host : discovered_hosts) {
        targets.push_back(host.ip);
    }

    for (int i = 0; i < targets.size(); i++) {
        currentHostIndex = i;
        IPAddress host = targets[i];
        
        Serial.printf("Bruteforcing FTP on host %d/%d: %s\n", 
                     i + 1, targets.size(), host.toString().c_str());
        
        FTPBruteforce(host);

        // Maintenance
        esp_task_wdt_reset();
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    scanInProgress = false;
    Serial.println("FTP Bruteforce complete.");
    vTaskDelete(nullptr);
}

// Web Handlers

void handle_deauth(AsyncWebServerRequest* request) {
    // Example deauth actions here
    request->send(200, "text/plain", "Deauthentication started.");
}

void handle_port_scanning(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");

    response->print("[");  // Start of JSON array

    String hostJson;

    for (size_t i = 0; i < hosts.size(); i++) {
        hostJson = port_scanner(hosts[i]);

        if (i > 0) response->print(",");  // Add comma before next item if not first

        response->print(hostJson);

        Serial.println(hostJson);

        response->flush();  // Send data immediately to client

        delay(5);  // Let watchdog breathe and allow other tasks to run
        yield();
    }

    response->print("]");  // End of JSON array

    request->send(response);
}

void handle_update_start(AsyncWebServerRequest* request) {
    if (update_in_progress || hostScanTaskHandle != NULL) {
        request->send(200, "application/json", "{\"thing\":\"Host identification\",\"message\":\"scan already running\"}");
        return;
    }

    update_in_progress = true;
    scan_complete = false;
    hosts.clear();
    discovered_hosts.clear();

    xTaskCreatePinnedToCore(
        hostScanTask,
        "HostScanTask",
        8192,
        NULL,
        1,
        &hostScanTaskHandle,
        1
    );

    request->send(200, "application/json", "{\"thing\":\"Host identification\",\"message\":\"scan started\"}");
}

void handle_update_status(AsyncWebServerRequest* request) {
    if (update_in_progress) {
        request->send(200, "application/json", "{\"thing\":\"Host identification\",\"message\":\"scan running\"}");
        return;
    }

    if (scan_complete) {
        String json = "[";
        for (size_t i = 0; i < discovered_hosts.size(); i++) {
            const HostInfo& h = discovered_hosts[i];
            char macStr[18];
            sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                h.mac[0], h.mac[1], h.mac[2], h.mac[3], h.mac[4], h.mac[5]);
            json += "{\"ip\":\"" + h.ip.toString() + "\", \"mac\":\"" + String(macStr) + "\"}";
            if (i < discovered_hosts.size() - 1) json += ",";
        }
        json += "]";

        request->send(200, "application/json", json);

        scan_complete = false;  // reset after reporting
        return;
    }

    request->send(200, "application/json", "{\"thing\":\"channel\",\"message\":\"AP channel is currently updating\"}");
}

void handle_beacon_spam_start(AsyncWebServerRequest* request) {
    if (beaconSpamTaskHandle != NULL) {
        request->send(200, "application/json", "{\"message\":\"Beacon spam already running\"}");
        return;
    }
    xTaskCreatePinnedToCore(
        beacon_spam_task,
        "BeaconSpamTask",
        4096,
        NULL,
        1,
        &beaconSpamTaskHandle,
        1
    );
    request->send(200, "application/json", "{\"message\":\"Beacon spam started\"}");
}

void handle_beacon_spam_status(AsyncWebServerRequest* request) {
    request->send(200, "application/json", "{\"name\":\"Fake_AP_\",\"numAP\":\"" + String(numAP) + "\"}");
}

void handle_macs_update(AsyncWebServerRequest* request) {
    update_mac_addresses_of_APs();
    request->send(200, "application/json", "{\"message\": \"MAC addresses updated\"}");
}

void handle_overclocking_start(AsyncWebServerRequest* request) {
    setCpuFrequencyMhz(240);
    isOverclockOn = true;
    int freq = getCpuFrequencyMhz();

    String json = "{\"overclockOn\":true,\"frequency\":" + String(freq) + "}";
    request->send(200, "application/json", json);
}

void handle_overclocking_stop(AsyncWebServerRequest* request) {
    setCpuFrequencyMhz(160);
    isOverclockOn = false;
    int freq = getCpuFrequencyMhz();

    String json = "{\"overclockOn\":false,\"frequency\":" + String(freq) + "}";
    request->send(200, "application/json", json);
}

void handle_overclocking_status(AsyncWebServerRequest* request) {
    bool overclockOn = (getCpuFrequencyMhz() > 80); 
    int freq = getCpuFrequencyMhz();
    
    String json = "{\"overclockOn\":" + String(overclockOn ? "true" : "false") + 
                  ",\"frequency\":" + String(freq) + "}";
    request->send(200, "application/json", json);
}

void handle_start_service_scan(AsyncWebServerRequest* request) {
    if (scanInProgress) {
        request->send(200, "text/plain", "Scan already in progress");
        return;
    }
    
    xTaskCreatePinnedToCore(
        serviceScanTask,    // Task function
        "ServiceScan",      // Task name
        10000,             // Stack size
        nullptr,            // Parameters
        1,                 // Priority
        &scanTaskHandle,    // Task handle
        0                  // Core
    );
    
    request->send(200, "text/plain", "Scan started");
}

void handle_scan_progress(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    if (scanInProgress) {
        response->printf("{\"status\":\"scanning\",\"progress\":%d,\"total\":%d}",
                         currentHostIndex, hosts.size());
    } else {
        response->print("{\"status\":\"idle\"}");
    }
    
    request->send(response);
}

void handle_service_results(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    response->print("[");
    
    for (size_t i = 0; i < scanResults.size(); i++) {
        if (i > 0) response->print(",");
        
        String escaped = scanResults[i].service;
        escaped.replace("\\", "\\\\");
        escaped.replace("\"", "\\\"");
        escaped.replace("\n", "\\n");
        escaped.replace("\r", "");
        
        response->printf("{\"IP\":\"%s\",\"Service\":\"%s\"}",
                         scanResults[i].ip.toString().c_str(),
                         escaped.c_str());
        hosts_service = scanResults;  // Update global service list
    }
    
    response->print("]");
    request->send(response);
}

void handle_status(AsyncWebServerRequest* request) {
    Serial.println("Starting status handling");

    // Calculate safe iteration count
    const size_t count = min(min(hosts.size(), discovered_hosts.size()), hosts_service.size());
    if (hosts.size() != discovered_hosts.size() || 
        hosts.size() != hosts_service.size()) {
        Serial.println("Error: Mismatched sizes in hosts, discovered_hosts, or hosts_service");
        request->send(500, "application/json", "{\"error\":\"Data mismatch\"}");
        return;
    }
    Serial.printf("Processing %d host entries\n", count);

    // Estimate max needed size: 150 bytes per entry + 2 for []
    String json;
    json.reserve(count * 150 + 2);
    json += "[";

    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            json += ",";
        }

        // Format MAC address
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 discovered_hosts[i].mac[0], discovered_hosts[i].mac[1],
                 discovered_hosts[i].mac[2], discovered_hosts[i].mac[3],
                 discovered_hosts[i].mac[4], discovered_hosts[i].mac[5]);

        // Escape service string manually inline
        String escapedService;
        const String& input = hosts_service[i].service;
        escapedService.reserve(input.length() + 10);
        for (size_t j = 0; j < input.length(); j++) {
            char c = input.charAt(j);
            switch (c) {
                case '\\': escapedService += "\\\\"; break;
                case '\"': escapedService += "\\\""; break;
                case '\n': escapedService += "\\n";  break;
                case '\r': escapedService += "\\r";  break;
                case '\t': escapedService += "\\t";  break;
                case '\b': escapedService += "\\b";  break;
                case '\f': escapedService += "\\f";  break;
                default:
                    if (c < ' ') {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04X", c);
                        escapedService += buf;
                    } else {
                        escapedService += c;
                    }
            }
        }

        // Build JSON object
        json += "{\"IP\":\"" + discovered_hosts[i].ip.toString() +
                "\",\"MAC\":\"" + String(macStr) +
                "\",\"Service\":\"" + escapedService + "\"}";
    }

    json += "]";

    if (count == 0) {
        json = "[]";
    }

    Serial.println("Sending JSON response");
    request->send(200, "application/json", json);
}

// Start scan endpoint
void handle_vuln_scanning(AsyncWebServerRequest* request) {
    if(scanInProgress) {
        request->send(423, "application/json", 
                    "{\"status\":\"error\",\"message\":\"Scan already in progress\"}");
        return;
    }

    if(xTaskCreatePinnedToCore(
        vuln_scanner_task,
        "VulnScanner",
        8192,
        NULL,
        1,
        NULL,
        1
    ) != pdPASS) {
        request->send(500, "application/json",
                    "{\"status\":\"error\",\"message\":\"Failed to start scan\"}");
    } else {
        request->send(200, "application/json",
                    "{\"status\":\"success\",\"message\":\"Scan started\"}");
    }
}

// Progress endpoint
void handle_vuln_scan_progress(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    if(scanInProgress) {
        response->printf("{\"status\":\"scanning\",\"progress\":%d,\"total\":%d}",
                       currentHostIndex, discovered_hosts.size());
    } else {
        response->print("{\"status\":\"idle\"}");
    }
    
    request->send(response);
}

// Results endpoint
void handle_vuln_scanning_results(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    response->print("{\"results\":[");
    for(size_t i = 0; i < vulnResults.size(); i++) {
        if(i > 0) response->print(",");
        
        // Escape JSON special characters
        String escaped = vulnResults[i];
        escaped.replace("\\", "\\\\");
        escaped.replace("\"", "\\\"");
        escaped.replace("\n", "\\n");
        
        response->printf("{\"id\":%d,\"result\":\"%s\"}", i, escaped.c_str());
    }
    response->print("]}");
    
    request->send(response);
}

void hanlde_SSHBruteforce_start(AsyncWebServerRequest* request) {
    if (scanInProgress) {
        request->send(423, "application/json", 
                      "{\"status\":\"error\",\"message\":\"Bruteforce already in progress\"}");
        return;
    }

    if (xTaskCreatePinnedToCore(
        SSHBruteforce_task,
        "SSHBruteforce",
        24000,  // Increased stack size for SSH Bruteforce
        NULL,
        1,
        NULL,
        1
    ) != pdPASS) {
        request->send(500, "application/json",
                      "{\"status\":\"error\",\"message\":\"Failed to start SSH Bruteforce\"}");
    } else {
        request->send(200, "application/json",
                      "{\"status\":\"success\",\"message\":\"SSH Bruteforce started\"}");
    }
}

void handle_SSHBruteforce_progress(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    if (scanInProgress) {
        response->printf("{\"status\":\"scanning\",\"progress\":%d,\"total\":%d}",
                         currentHostIndex, discovered_hosts.size());
    } else {
        response->print("{\"status\":\"idle\"}");
    }
    
    request->send(response);
}

void handle_SSHBruteforce_results(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    response->print("{\"results\":[");
    for (size_t i = 0; i < SSHBruteforce_results.size(); i++) {
        if (i > 0) response->print(",");
        
        const SSHbruteforceResult& result = SSHBruteforce_results[i];
        String escapedUsername = result.username;
        String escapedPassword = result.password;
        escapedUsername.replace("\\", "\\\\");
        escapedUsername.replace("\"", "\\\"");
        escapedPassword.replace("\\", "\\\\");
        escapedPassword.replace("\"", "\\\"");
        
        response->printf("{\"IP\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                         result.ip.toString().c_str(),
                         escapedUsername.c_str(),
                         escapedPassword.c_str());
    }
    response->print("]}");
    
    request->send(response);
}

void hanlde_FTPBruteforce_start(AsyncWebServerRequest* request) {
    if (scanInProgress) {
        request->send(423, "application/json", 
                      "{\"status\":\"error\",\"message\":\"Bruteforce already in progress\"}");
        return;
    }

    if (xTaskCreatePinnedToCore(
        FTPBruteforce_task,
        "FTPBruteforce",
        24000,  // Increased stack size for FTP Bruteforce
        NULL,
        1,
        NULL,
        1
    ) != pdPASS) {
        request->send(500, "application/json",
                      "{\"status\":\"error\",\"message\":\"Failed to start FTP Bruteforce\"}");
    } else {
        request->send(200, "application/json",
                      "{\"status\":\"success\",\"message\":\"FTP Bruteforce started\"}");
    }
}

void handle_FTPBruteforce_progress(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    if (scanInProgress) {
        response->printf("{\"status\":\"scanning\",\"progress\":%d,\"total\":%d}",
                         currentHostIndex, discovered_hosts.size());
    } else {
        response->print("{\"status\":\"idle\"}");
    }
    
    request->send(response);
}

void handle_FTPBruteforce_results(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    
    response->print("{\"results\":[");
    for (size_t i = 0; i < FTPBruteforce_results.size(); i++) {
        if (i > 0) response->print(",");
        
        const FTPbruteforceResult& result = FTPBruteforce_results[i];
        String escapedUsername = result.username;
        String escapedPassword = result.password;
        escapedUsername.replace("\\", "\\\\");
        escapedUsername.replace("\"", "\\\"");
        escapedPassword.replace("\\", "\\\\");
        escapedPassword.replace("\"", "\\\"");
        
        response->printf("{\"IP\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                         result.ip.toString().c_str(),
                         escapedUsername.c_str(),
                         escapedPassword.c_str());
    }
    response->print("]}");
    
    request->send(response);
}