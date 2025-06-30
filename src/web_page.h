#ifndef WEB_PAGE_H
#define WEB_PAGE_H

#include <ESPAsyncWebServer.h>

// Declare the global server object (extern because it is defined elsewhere)
extern AsyncWebServer server;

// Declare other global variables used across files
extern bool wifi_busy;
extern bool pending_update;
extern unsigned long start_update;

// Declare all handler functions with correct signatures:
// Note: Each handler takes a pointer to AsyncWebServerRequest
void handle_root(AsyncWebServerRequest* request);
void handle_deauth(AsyncWebServerRequest* request);
void handle_port_scanning(AsyncWebServerRequest* request);
void handle_beacon_spam(AsyncWebServerRequest* request);
void handle_update_start(AsyncWebServerRequest* request);
void handle_update_status(AsyncWebServerRequest* request);
void handle_beacon_spam_start(AsyncWebServerRequest* request);
void handle_beacon_spam_status(AsyncWebServerRequest* request);
void handle_macs_update(AsyncWebServerRequest* request);
void handle_overclocking_status(AsyncWebServerRequest* request);
void handle_overclocking_start(AsyncWebServerRequest* request);
void handle_overclocking_stop(AsyncWebServerRequest* request);
void handle_status(AsyncWebServerRequest* request);
void handle_start_service_scan(AsyncWebServerRequest* request);
void handle_scan_progress(AsyncWebServerRequest* request);
void handle_service_results(AsyncWebServerRequest* request);
void handle_vuln_scanning_results(AsyncWebServerRequest* request);
void handle_vuln_scanning(AsyncWebServerRequest* request);
void handle_vuln_scan_progress(AsyncWebServerRequest* request);
void handle_SSHBruteforce_results(AsyncWebServerRequest* request);
void handle_SSHBruteforce_progress(AsyncWebServerRequest* request);
void hanlde_SSHBruteforce_start(AsyncWebServerRequest* request);
void handle_FTPBruteforce_results(AsyncWebServerRequest* request);
void handle_FTPBruteforce_progress(AsyncWebServerRequest* request);
void hanlde_FTPBruteforce_start(AsyncWebServerRequest* request);

#endif // WEB_PAGE_H