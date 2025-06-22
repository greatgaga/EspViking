#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>
#include <vector>
#include <cstdint>
#include <WiFi.h>

struct HostInfo {
    IPAddress ip;
    uint8_t mac[6];
};

struct HostService {
    IPAddress ip;
    String service;
};

extern const char* ssid;
extern const char* password;
extern std::vector<IPAddress> hosts;
extern std::vector<uint8_t> deauth_frame;
extern std::vector<uint8_t> beacon_frame;
extern std::vector<HostInfo> discovered_hosts;
extern int channel;
extern int port;    
extern const String html_page;
extern std::vector<std::vector<uint8_t> > mac_addresses_of_APs;
extern bool wifi_busy;
extern unsigned long start_update;
extern bool pending_update;
extern String json;
extern int numAP;
extern std::vector<HostService> hosts_service;

#endif