#include <WiFi.h>
#include "FS.h"
#include "LittleFS.h"
#include <networking_tools.h>
#include <config.h>
#include <vector>
#include <ESPAsyncWebServer.h>
#include "esp_task_wdt.h"
#include <esp_wifi.h>
#include <web_page.h>

// Your WiFi credentials
const char* ssid = "";
const char* password = "";

// Your API key for the server (optinal, but without it you wont be able to use some features)
String API_key= "";

std::vector<IPAddress> hosts = {};
std::vector<HostInfo> discovered_hosts = {};
std::vector<HostService> hosts_service = {};
std::vector<HostPorts> hosts_ports = {};
std::vector<uint8_t> deauth_frame;
std::vector<uint8_t> beacon_frame;
std::vector<std::vector<uint8_t> > mac_addresses_of_APs;
std::vector<SSHbruteforceResult> SSHBruteforce_results = {};
std::vector<FTPbruteforceResult> FTPBruteforce_results = {};
String json = "";
int numAP = 1;

int channel = -1;
// feel free to change the port ESP32 uses for communication with clients
int port = 80;

// html code made for testing service scanning
/*
const char htmlPage[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <title>Power belongs to the people who take it - Tyrell Wellick</title>
  <meta name="x-server" content="ESP32-WEB-V1.0">đ
  <!-- ServerID: ESP32-ScannerTarget -->
</head>
<body>
  <h1>Power belongs to the people who take it - Tyrell Wellick</h1>
</body>
</html>
)rawliteral";
*/

void setup() {
    esp_task_wdt_init(50, true);
    esp_task_wdt_add(NULL);

    Serial.begin(115200);

    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED) {
        Serial.print('.');
        delay(500);
    }

    Serial.println("\nConnected to WiFi!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());

    if (!LittleFS.begin(true)) {
        Serial.println("LittleFS Mount Failed");
        return;
    }

    // these are IP addresses made for debugging(so you dont have to wait for host_identifier() to finish)
    hosts.push_back(IPAddress(192, 168, 40, 93));

    // initializing all the needed features for web page

    // init of all funcs
    server.on("/api/port_scan", HTTP_GET, handle_port_scanning);
    server.on("/api/deauth", HTTP_GET, handle_deauth);
    server.on("/api/update/start", HTTP_GET, handle_update_start);
    server.on("/api/update/status", HTTP_GET, handle_update_status);
    server.on("/api/beacon/start", HTTP_GET, handle_beacon_spam_start);
    server.on("/api/beacon/status", HTTP_GET, handle_beacon_spam_status);
    server.on("/api/beacon/update_MACs", HTTP_GET, handle_macs_update);
    server.on("/api/CPU/overclocking/status", HTTP_GET, handle_overclocking_status);
    server.on("/api/CPU/overclocking/start", HTTP_GET, handle_overclocking_start);
    server.on("/api/CPU/overclocking/stop", HTTP_GET, handle_overclocking_stop);
    server.on("/api/status", HTTP_GET, handle_status);
    server.on("/api/scan_progress", HTTP_GET, handle_scan_progress);
    server.on("/api/service_results", HTTP_GET, handle_service_results);
    server.on("/api/start_service_scan", HTTP_GET, handle_start_service_scan);
    server.on("/api/vuln_scan_start", HTTP_GET, handle_vuln_scanning);
    server.on("/api/vuln_scan_progress", HTTP_GET, handle_vuln_scan_progress);
    server.on("/api/vuln_scan_results", HTTP_GET, handle_vuln_scanning_results);
    server.on("/api/SSHBruteforce_results", HTTP_GET, handle_SSHBruteforce_results);
    server.on("/api/SSHBruteforce_start", HTTP_GET, hanlde_SSHBruteforce_start);
    server.on("/api/SSHBruteforce_progress", HTTP_GET, handle_SSHBruteforce_progress);
    server.on("/api/FTPBruteforce_results", HTTP_GET, handle_FTPBruteforce_results);
    server.on("/api/FTPBruteforce_start", HTTP_GET, hanlde_FTPBruteforce_start);
    server.on("/api/FTPBruteforce_progress", HTTP_GET, handle_FTPBruteforce_progress);

    // supresing errors
    server.on("/favicon.ico", HTTP_GET, [](AsyncWebServerRequest *request){
        request->send(204);  // No content, quiets the browser
    });

    // Serve static pages for specific paths only
    server.serveStatic("/port_scanning", LittleFS, "/port_scanning/").setDefaultFile("index.html");
    server.serveStatic("/beacon_spam", LittleFS, "/beacon_spam/").setDefaultFile("index.html");
    server.serveStatic("/overclock", LittleFS, "/overclock/").setDefaultFile("index.html");
    server.serveStatic("/update", LittleFS, "/update/").setDefaultFile("index.html");
    server.serveStatic("/service_identifier", LittleFS, "/service_identifier/").setDefaultFile("index.html");
    server.serveStatic("/status", LittleFS, "/status/").setDefaultFile("index.html");
    server.serveStatic("/vuln_scanning", LittleFS, "/vuln_scanning/").setDefaultFile("index.html");
    server.serveStatic("/SSHBruteforce", LittleFS, "/SSHBruteforce/").setDefaultFile("index.html");
    server.serveStatic("/FTPBruteforce", LittleFS, "/FTPBruteforce/").setDefaultFile("index.html");

    // Catch-all for root-level static files only (not ALL paths)
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
        request->send(LittleFS, "/index.html", "text/html");
    });

    // uncomment to test version_scanner()
    /*
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        AsyncWebServerResponse* response = request->beginResponse_P(200, "text/html", htmlPage);
        response->addHeader("Server", "ESP32-WebServer/1.0");
        request->send(response);
    });
    */

    server.begin();

    Serial.println("HTTP server started");

    Serial.println((String)getCpuFrequencyMhz() + "MHz is current frequency of CPU");

    esp_task_wdt_reset();
    get_channel();
    scan_hosts_ips();
    mac_from_arp();
    esp_task_wdt_reset();

    Serial.println(discovered_hosts.size());
    for (size_t i = 0; i < discovered_hosts.size(); i++) {
        Serial.printf("Host %d - MAC: ", (int)i);
        for (int j = 0; j < 6; j++) {
            if (discovered_hosts[i].mac[j] < 0x10) Serial.print("0");
            Serial.print(discovered_hosts[i].mac[j], HEX);
            if (j < 5) Serial.print(":");
        }
        Serial.println();
    }
}

void loop() {
    esp_task_wdt_reset();

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi lost connection. Attempting reconnect...");
        WiFi.reconnect();
        unsigned long startAttempt = millis();
        while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < 10000) {
            delay(500);
            Serial.print(".");
            esp_task_wdt_reset();
        }
        if (WiFi.status() == WL_CONNECTED) {
            Serial.println("\nReconnected to WiFi!");
        } else {
            Serial.println("\nFailed to reconnect.");
        }
    }
    delay(200);
}