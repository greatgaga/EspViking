#ifndef NETWORKING_TOOLS_H
#define NETWORKING_TOOLS_H

#include <WiFi.h>
#include <Arduino.h>
#include <vector>
#include <ESPAsyncWebServer.h>

String port_scanner(IPAddress);
void deauth();
void mac_from_arp();
void host_identifier();
void deauth_client(std::vector<uint8_t>);
void get_channel();
void beacon_spam();
void create_beacon_frame(int);
void update_mac_addresses_of_APs();
void host_identifiter_for_debuging();
String version_scanner(IPAddress);
void scan_hosts_ips();
void read_arp_table_for_ips(struct netif *iface);

#endif // NETWORKING_TOOLS_H