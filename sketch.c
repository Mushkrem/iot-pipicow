#include <WiFi.h>
#include <PubSubClient.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <time.h>
#include "hardware/watchdog.h"
#include <Crypto.h>
#include <SHA256.h>
#include <stdio.h>
#include "pico/multicore.h"
#include <pico/stdlib.h>

// WiFi credentials 
const char* SSID = "SSID";
const char* PASSWORD = "PASS";

// MQTT credentials
const char* MQTT_SERVER = "CLUSTER_ID.s1.eu.hivemq.cloud";
const int MQTT_PORT = 8883;
const char* MQTT_USERNAME = "CLUSTER_PASS";
const char* MQTT_PASSWORD = "CLUSTER_LOGIN";

WiFiClientSecure client;
PubSubClient mqtt_client(client);

static const char *encrypt_cert PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)EOF";

enum LogLevels {
  INFO,
  WARNING,
  ERROR,
  SUCCESS,
  DEBUG,
  DEFAULT
};

struct MqttError {
  int code;
  const char* message;
};

const MqttError mqtt_errors[] = {
  { -4, "The server didn't respond within the keepalive time" },
  { -3, "The network connection was broken" },
  { -2, "The network connection failed" },
  { -1, "The client is disconnected cleanly" },
  { 0, "The client is connected" },
  { 1, "The server doesn't support the requested version of MQTT" },
  { 2, "The server rejected the client identifier" },
  { 3, "The server was unable to accept the connection" },
  { 4, "The username/password were rejected" },
  { 5, "The client was not authorized to connect" },
};

const int mqtt_error_count = sizeof(mqtt_errors) / sizeof(MqttError);

const char* mqtt_error_literal(int code) {
  for (int i = 0; i < mqtt_error_count; ++i) {
    if (mqtt_errors[i].code == code) {
      static char buffer[64];
      snprintf(buffer, sizeof(buffer), "%d: \"%s\"", code, mqtt_errors[i].message);
      return buffer;
    }
  }

  static char unknown[32];
  snprintf(unknown, sizeof(unknown), "%d : \"Unrecognized error\"", code);
  return unknown;
}

bool instantenous = false;
void instant_impl() { instantenous = true; };
// Global logger with colors
void logger_impl(const char* text, LogLevels level, bool ln) {
  const char* color_code;
  switch(level) {
    case INFO: color_code = "\x1b[36m"; break;
    case WARNING: color_code = "\x1b[93m"; break;
    case ERROR: color_code = "\x1b[91m"; break;
    case SUCCESS: color_code = "\x1b[92m"; break;
    case DEBUG: color_code = "\x1b[90m"; break;
    case DEFAULT: color_code = ""; break;
  }

  Serial.print(color_code);

  // Print each character one at a time with a delay
  if(!instantenous) {
    for (size_t i = 0; text[i] != '\0'; ++i) {
      Serial.print(text[i]);
      delay(50); // 50ms delay between characters
    }
  } else {
    Serial.print(text);
  }

  if (ln) Serial.println();
  Serial.print("\x1b[0m"); // Reset color
  instantenous = false;
}
void print_impl(const char* text, LogLevels level) {
  logger_impl(text, level, false);
}
void print_impl_nl(const char* text, LogLevels level) {
  logger_impl(text, level, true);
}

typedef struct {
  void (*print)(const char *text, LogLevels level);
  void (*println)(const char *text, LogLevels level);
  void (*next_instant)();
} Logger;
Logger g_log = { .print = print_impl, .println = print_impl_nl, .next_instant = instant_impl };

void timer_start_impl();
const char* timer_delta_impl();

// Global timer with delta time
typedef struct {
  uint16_t ref_time;
  void (*start)();
  const char* (*delta)();
} timer_tv;
timer_tv g_timer = { 0, .start = timer_start_impl, .delta = timer_delta_impl };

void timer_start_impl() {
  g_timer.ref_time = millis();
}
const char* timer_delta_impl() {
  static char buffer[10];
  sprintf(buffer, "%us", (millis() - g_timer.ref_time)/1000);
  return buffer;
}

String rssi_to_bars(int32_t rssi) {
  if (-80 >= rssi) {
    // Poor signal
    return "\t\x1b[93m▃ \x1b[90m▅ ▉\x1b[0m";
  } else if (-50 >= rssi) {
    // Okay signal
    return "\t\x1b[93m▃ ▅ \x1b[90m▉\x1b[0m";
  } else {
    // Excellent signal strength
    return "\t\x1b[92m▃ ▅ ▉\x1b[0m";
  }
}

void connect_to_wifi(const char* SSID, const char* PASS) {
  g_timer.start(); // Start the timer (time elapsed)
  
  WiFi.mode(WIFI_STA); // Station mode
  WiFi.setHostname(g_device_id);

  int retries = 0;
  const int MAX_RETRIES = 3;
  while(WL_CONNECTED != WiFi.status() && MAX_RETRIES > retries) { // Attempts to connect to WiFi
    if (0 != retries) {
      WiFi.disconnect(true);
      g_log.print(" Failure!", ERROR);

      g_log.println(" (retrying..)", DEBUG);
      delay(500);
    }

    WiFi.begin(SSID, PASS); // Begin the scanner.

    g_log.print("Waiting for WiFi", INFO);

    unsigned long t_start = millis();
    const unsigned long TIMEOUT = 8000; // 8 seconds
    while (WL_CONNECTED != WiFi.status() && millis() - t_start < TIMEOUT) {
      g_log.next_instant(); // Prints the next line instantenously
      g_log.print(".", DEFAULT);
      delay(500);
    }

    retries++;
  }

  if (WL_CONNECTED != WiFi.status()) {
    g_log.println("", DEFAULT);
    g_log.println("Couldn't connect to a WiFi network. Restarting the board.", ERROR);
    delay(1500);

    watchdog_enable(1, 1); // Triggers a reset
    while (true); // Wait for watchdog to ,,kick in''
  }

  g_log.print(" Success!", SUCCESS);

  g_log.print(" (took ", DEBUG);
  g_log.print(g_timer.delta(), DEBUG);
  g_log.println(")", DEBUG);

  g_log.print("IP address: ", INFO);
  g_log.print(WiFi.localIP().toString().c_str(), DEFAULT);

  g_log.next_instant();
  g_log.println(rssi_to_bars(WiFi.RSSI()).c_str(), SUCCESS);
}

void set_clock() {
  g_timer.start(); // Start the timer
  setenv("TZ", "CET-1CEST-2,M3.5.0,M10.5.0/3", 1); // Setting correct timezone offset  
  tzset();
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  g_log.print("Waiting for time", INFO);
  time_t now = time(nullptr);
  while (now < 24 * 3600) {
    g_log.next_instant();
    g_log.print(".", DEFAULT);
    now = time(nullptr);
    delay(500);
  }
  g_log.print(" Success!", SUCCESS);

  g_log.print(" (took ", DEBUG);
  g_log.print(g_timer.delta(), DEBUG);
  g_log.println(")", DEBUG);

  struct tm timeinfo;
  localtime_r(&now, &timeinfo);

  g_log.print("Current time: ", INFO);
  g_log.println(asctime(&timeinfo), DEFAULT);
}

// The id of this board
// 12 chars + null terminator
char g_device_id[13];

void mqtt_reconnect() {
  // Loop until we're reconnected
  while(!mqtt_client.connected()) {
    g_timer.start(); // Start the timer (time elapsed)
    g_log.print("Waiting for ", INFO);
    // Advancing the starting address of the pointer by 33
    // So it's skipping the MD5 hash part. 
    g_log.print(MQTT_SERVER + 33, DEBUG);
    if (mqtt_client.connect(g_device_id, MQTT_USERNAME, MQTT_PASSWORD)) {
      g_log.print(" Success!", SUCCESS);
      g_log.print(" (took ", DEBUG);
      g_log.print(g_timer.delta(), DEBUG);
      g_log.println(")", DEBUG);
      g_log.println("", DEFAULT);

      // Subscribe to 'BROADCAST' channel 
      // That is where the arduino will announce it exists
      mqtt_client.subscribe("BROADCAST");

      // Subscribe to its own direct communication topic.
      mqtt_client.subscribe(g_device_id);

    } else {
      g_log.println(" Failure!", ERROR);
      g_log.println(mqtt_error_literal(mqtt_client.state()), ERROR);
      delay(2500);
    }
  }
}

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
  if (length == 0 ) return;
  if (String(topic) == "BROADCAST") {
    // requesting for the id of all listening devices
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s%s", "@", g_device_id);
    if (payload[0] == '?') mqtt_client.publish("BROADCAST", buffer);
  } else {
    // direct commands
    g_log.println("Unrecognized command received", DEBUG);
  }
}

const int R = 11;
const int G = 12;
const int B = 13;
void set_color(int r, int g, int b) {
  analogWrite(R, 255 - r);
  analogWrite(G, 255 - g);
  analogWrite(B, 255 - b);
}

unsigned long blink_interval = 150; // Time between color flips (ms)
unsigned long last_blink_time = 0;
bool is_on = false;

void blink(int r, int g, int b) {
  unsigned long current_time = millis();
  if (current_time - last_blink_time >= blink_interval) {
    last_blink_time = current_time;
    is_on = !is_on;
    
    if (is_on)
      set_color(r, g, b); // ON
    else
      set_color(0, 0, 0); // OFF
  }
}

void core1_task() {
  if (!WiFi.connected()) {
    blink(0, 0, 255);
  }
  else if (!mqtt_client.connected()) {
    blink(255, 0, 0);
  }
  else if (mqtt_client.connected()) {
    set_color(255, 255, 0);
  }
  else {
    set_color(0, 0, 0);
  }

  tight_loop_contents();
}

void core1_entry() {
  tight_loop_contents();
  while (true) {
    yield();
    core1_task();
    delay(50);
  }
}

void setup() {
  Serial.begin(115200);
  delay(2500);

  pinMode(R, OUTPUT);
  pinMode(G, OUTPUT);
  pinMode(B, OUTPUT);

  /// \tag::setup_multicore[]

  multicore_launch_core1(core1_entry);
  tight_loop_contents();

  /// \end::setup_multicore[]

  delay(2500); // Needed to capture serial data with the 'SimpleSerial' terminal
               // SimpleSerial allows for ANSI escape codes in contrast to Arduino's IDE built-in terminal, which does not.
  g_log.next_instant(); // Prints the next line instantenously
  g_log.println("[START INIT]\n", WARNING);
  
  //*** Creating unique-ish ID address of the Arduino ***//
  SHA256 sha256;
  byte hash[sha256.hashSize()];

  // Creating a buffer combining WiFi's SSID and Arduino's local IP address.
  static char buffer[256];
  snprintf(buffer, sizeof(buffer), "%s%s", SSID, WiFi.localIP().toString().c_str());

  // Creating a hash from the buffer
  sha256.reset();
  sha256.update((const byte*)buffer, strlen(buffer));
  sha256.finalize(hash, sizeof(buffer));

  // Truncating the hash to the first 12 characters.
  for (int i = 0; i < 6; ++i) {
    sprintf(&g_device_id[i*2], "%02x", hash[i]);
  }
  g_device_id[12] = '\0'; // Null terminator

  //*** Connecting to WiFi. ***//
  connect_to_wifi(SSID, PASSWORD);

  // Additional spacing.
  g_log.println("", DEBUG);

  //*** Setting the correct clock for certification. ***//
  set_clock();

  // Setting the SecureClient's Certificate Authority to 'Let's Encrypt!' root certificate.
  // Expires on 15/01/2038
  // And that is when this code might stop working.
  client.setCACert(encrypt_cert);

  //*** Setting up the mqtt connection ***//
  mqtt_client.setServer(MQTT_SERVER, MQTT_PORT);
  mqtt_client.setCallback(mqtt_callback);

  // Begin initial connection
  // Execution will be stuck until Arduino connects to the server.
  mqtt_reconnect();
  // As it is possible for the Arduino to lose connection, all configs are inside the reconnect() function.

  g_log.next_instant();
  g_log.println("[END INIT]", ERROR);
}

void loop() {
  if (!mqtt_client.connected()) {
    mqtt_reconnect();
  }
  mqtt_client.loop();
}
