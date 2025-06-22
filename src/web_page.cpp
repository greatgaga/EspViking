#include "web_page.h"
#include "config.h"
#include "networking_tools.h"
#include <ESPAsyncWebServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <Arduino.h>
#include <LittleFS.h>

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

void handle_service_scanning(AsyncWebServerRequest* request) {
    AsyncResponseStream *response = request->beginResponseStream("application/json");
    response->print("[");
    HostService service;
    hosts_service = {};

    for (size_t i = 0; i < hosts.size(); i++) {
        String result = version_scanner(hosts[i]);

        service.ip = hosts[i];
        service.service = result;
        hosts_service.push_back(service);

        Serial.println(result);

        if (i > 0) response->print(",");

        result.replace("\\", "\\\\");
        result.replace("\"", "\\\"");
        result.replace("\n", "\\n");
        result.replace("\r", "");

        response->print("{\"IP\":\"" + hosts[i].toString() + 
                        "\",\"Service\":\"" + result + "\"}");
        response->flush();
        yield();
    }
    response->print("]");
    request->send(response);
}

void handle_status(AsyncWebServerRequest* request) {
    Serial.println("Starting handling status");
    String json = "[";
    for (int i = 0; i < min(hosts.size(), min(discovered_hosts.size(), hosts_service.size())); i++){
        if (i > 0){
            json += ", ";
        }
        char macStr[18];
        sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                discovered_hosts[i].mac[0], discovered_hosts[i].mac[1],
                discovered_hosts[i].mac[2], discovered_hosts[i].mac[3],
                discovered_hosts[i].mac[4], discovered_hosts[i].mac[5]);

        json += "{\"IP\":\"" + discovered_hosts[i].ip.toString() + 
                "\",\"MAC\":\"" + String(macStr) + 
                "\",\"Service\":\"" + hosts_service[i].service + "\"}";
    }
    json += "]";
    Serial.println("Done handling status");
    request->send(200, "application/json", json);
}