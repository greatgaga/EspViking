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
        53, 80, 110, 143, 443,
        445, 3306, 3389, 8080, 5060
    };

    Serial.print("\nStarting port scan.");

    String json1;
    for (size_t i = 0; i < ports.size(); i++) {
        if (i > 0) {
            json1 += ",";
        }

        json1 += "{";
        json1 += "\"ip\":\"" + IP.toString() + "\",";
        json1 += "\"port\":" + String(ports[i]) + ",";

        WiFiClient client;
        bool open = client.connect(IP, ports[i], 50);  // 50ms timeout

        json1 += "\"open\":" + String(open ? "true" : "false");
        client.stop();

        json1 += "}";

        delay(2);  // Slightly longer delay helps with socket stability
        if (i % 5 == 0) yield();
    }
    Serial.print("\nPort scan complete.");
    return json1;
}

// read IPs from ARP table because its faster than pinging each host(TCP is layer 4 of OSI model, while doing this with ARP requests takes place on 2 layer of OSI model(more low level -> faster)) 
void read_arp_table_for_ips(struct netif *iface) {
    Serial.println("\nread_arp_table_for_ips called");
    hosts.clear();
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip_return;
        eth_addr *eth_return;
        if (etharp_get_entry(i, &ip_return, &iface, &eth_return)) {
            hosts.push_back(IPAddress(ip_return -> addr));
            Serial.println("Done adding host " + IPAddress(ntohl(ip_return -> addr)).toString() + " to the hosts");
        }
    }
}

void scan_hosts_ips() {
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

    uint16_t arpRequestDelayMs = 40;
    uint16_t tableReadCounter = 0;

    Serial.println("\ninit completed");

    // checking every host on network(building ARP table)
    for (uint32_t ip_le = networkaddress + 1; ip_le < broadcastaddress; ip_le++){
        if (ip_le == localIP){continue;}

        // converting from little-endian to big-endian
        ip4_addr_t ip_be{htonl(ip_le)};

        IPAddress ip_obj(ip_le);
        Serial.println("\nchecking if " + ip_obj.toString() + " exists");

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


void host_identifier() {
    Serial.print("\nHost identifier called.");
    IPAddress localIP = WiFi.localIP();
    uint8_t baseIP[3] = {localIP[0], localIP[1], localIP[2]};

    for (int ip = 2; ip < 255; ip++) {
        IPAddress target(baseIP[0], baseIP[1], baseIP[2], ip);
        Serial.println("\nLooking if host " + target.toString() + " exists");

        if (Ping.ping(target)) {
            Serial.println("Host " + target.toString() + " exists");
            hosts.push_back(target);
        }

        yield();  // important to allow async_tcp task to run!

        delay(1);

        esp_task_wdt_reset();
    }
    Serial.print("\nHost identifier done.");
}

/*
void host_identifiter_for_debuging() {
    Serial.println("\nStarting host identification for debuging");
    for (const auto& ip : hosts){
        Ping.ping(ip);
    }
    Serial.println("\nHost identification for debuging finished");
}
*/

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

String version_scanner(IPAddress target) {
    String versions = "Service not found";
    // fell free to change the ports below
    std::vector<int> ports = {21, 22, 23, 25, 53, 80, 110, 139, 143, 161,
                              443, 445, 8080, 8443, 10000, 5357, 8291, 2000, 5000, 5001};

    for (int i = 0; i < ports.size(); i++) {
        Serial.printf("\nConnecting to host %s %d\n", target.toString().c_str(), ports[i]);

        if (client.connect(target, ports[i])) {
            Serial.println("Connected to the target.");

            String line = "";

            // Read any initial banner (some servers send it automatically)
            unsigned long startTime = millis();
            while (!client.available() && millis() - startTime < 1000) {
                delay(50);
                esp_task_wdt_reset();
            }
            if (client.available()) {
                line = client.readStringUntil('\n');
                Serial.println(line);
                if (line.length() > 0) {
                    versions += "Port " + String(ports[i]) + " banner: " + line + "\n";
                }
            }

            if (line.length() == 0) {
                // no banner, try HTTP GET request
                client.print("GET / HTTP/1.1\r\n");
                client.print("Host: ");
                client.print(target.toString());
                client.print("\r\n");
                client.print("Connection: close\r\n\r\n");

                startTime = millis();
                while (!client.available() && millis() - startTime < 3000) {
                    delay(50);
                    esp_task_wdt_reset();
                }

                while (client.available()) {
                    line = client.readStringUntil('\n');
                    line.trim();
                    if (line.startsWith("Server: ")) {
                        Serial.println("Server Info: " + line);
                        versions += "Port " + String(ports[i]) + " " + line + "\n";
                    }
                }
            }

            client.stop();
        } else {
            Serial.println("Port is closed or filtered");
        }
        esp_task_wdt_reset();
    }
    Serial.println("Detected versions:\n" + versions);
    return versions;
}