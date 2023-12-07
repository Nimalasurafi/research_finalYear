#include <Arduino.h>
#include <AES.h>
#include <DHT.h>
#include <WiFi.h>               //we are using the ESP32
#include <Firebase_ESP_Client.h>

//Provide the token generation process info.
#include "addons/TokenHelper.h"
//Provide the RTDB payload printing info and other helper functions.
#include "addons/RTDBHelper.h"


#define DHTTYPE DHT11
#define DHTPIN 2

DHT dht(DHTPIN, DHTTYPE);

// Insert your network credentials
#define WIFI_SSID "Nimalasurafi"
#define WIFI_PASSWORD "surafi2022"

// Insert Firebase project API Key
#define API_KEY "AIzaSyCU9D5W-9tbToi6s8sw0yq1RVANQur78fw"

// Insert RTDB URLefine the RTDB URL */
#define DATABASE_URL "https://research-1a41e-default-rtdb.firebaseio.com/" 

//Define Firebase Data object
FirebaseData fbdo;

FirebaseAuth auth;
FirebaseConfig config;

unsigned long sendDataPrevMillis = 0;
int count = 0;
bool signupOK = false;   

struct RSAKey {
    long long int modulus;
    long long int exponent;
};

long long int mod_pow(long long int base, long long int exponent, long long int modulus) {
    long long int result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

long long int gcd(long long int a, long long int b) {
    while (b != 0) {
        long long int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

long long int mod_inverse(long long int a, long long int m) {
    for (long long int i = 1; i < m; i++) {
        if ((a * i) % m == 1) {
            return i;
        }
    }
    return 0; // This should not happen for valid RSA keys
}

class RSA {
private:
    long long int p, q, n, phi, e, d;

public:
    RSA() {
        initialize();
    }

    void initialize() {
        // Generate random primes (for simplicity, you may want to improve the prime generation)
        p = 61;
        q = 53;

        n = p * q;
        phi = (p - 1) * (q - 1);

        // Choose public key 'e'
        e = 17; // Typically, 65537 is a commonly used value

        // Calculate private key 'd'
        d = mod_inverse(e, phi);
    }

    long long int encrypt(long long int message) {
        return mod_pow(message, e, n);
    }

    long long int decrypt(long long int encrypted_text) {
        return mod_pow(encrypted_text, d, n);
    }
};

void rsa_encrypt(const byte* input, int inputLength, byte* output, RSAKey key) {
    RSA rsa;
    rsa.initialize();

    for (int i = 0; i < inputLength; i++) {
        output[i] = rsa.encrypt(input[i]);
    }
}

void rsa_decrypt(const byte* input, int inputLength, byte* output, RSAKey key) {
    RSA rsa;
    rsa.initialize();

    for (int i = 0; i < inputLength; i++) {
        output[i] = rsa.decrypt(input[i]);
    }
}

byte aesKey[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

byte iv[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

AES aes;

void setup() {
    Serial.begin(9600);
    dht.begin();

      Serial.begin(9600);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED){
    Serial.print(".");
    delay(300);
  }
  Serial.println();
  Serial.print("Connected with IP: ");
  Serial.println(WiFi.localIP());
  Serial.println();

  /* Assign the api key (required) */
  config.api_key = API_KEY;

  /* Assign the RTDB URL (required) */
  config.database_url = DATABASE_URL;

  /* Sign up */
  if (Firebase.signUp(&config, &auth, "", "")){
    Serial.println("ok");
    signupOK = true;
  }
  else{
    Serial.printf("%s\n", config.signer.signupError.message.c_str());
  }

  /* Assign the callback function for the long running token generation task */
  config.token_status_callback = tokenStatusCallback; //see addons/TokenHelper.h
  
  Firebase.begin(&config, &auth);
  Firebase.reconnectWiFi(true);
}


void loop() {
    delay(60000); // Delay for one minute (60,000 milliseconds)

    float temperature = dht.readTemperature();

    if (!isnan(temperature)) {
        // Convert temperature to a string
        String temperatureStr = String(temperature, 2);

        // Encrypt the temperature string using AES
        byte encryptedData[16];
        aes.do_aes_encrypt((byte*)temperatureStr.c_str(), temperatureStr.length(), encryptedData, aesKey, 128, iv);

        // Encrypt the AES key using RSA public key
        byte encryptedAESKey[16];
        rsa_encrypt(aesKey, sizeof(aesKey), encryptedAESKey, { 0xCB90F4F5D8AAB6E2, 0x11 });

        // Decrypt the AES key using RSA private key (just for illustration)
        byte decryptedAESKey[16];
        rsa_decrypt(encryptedAESKey, sizeof(encryptedAESKey), decryptedAESKey, { 0xCB90F4F5D8AAB6E2, 0x3917F4BCF81D406D });

        // Print original temperature value
        //Serial.print("Original Temperature: ");
        //Serial.print(temperature);
        //Serial.println(" °C");

        // Print encrypted data
        Serial.println("Encrypted Data:");
        for (int i = 0; i < 16; i++) {
            Serial.print(encryptedData[i], HEX);
            Serial.print(" ");
        }

        // Print encrypted AES key (for illustration purposes)
        Serial.println("\nEncrypted AES Key:");
        for (int i = 0; i < sizeof(encryptedAESKey); i++) {
            Serial.print(encryptedAESKey[i], HEX);
            Serial.print(" ");
        }
          // Store encrypted temperature and AES key in Firebase
        if (Firebase.ready() && signupOK) {
            // Write encrypted temperature to the database path
            Firebase.RTDB.setBlob(&fbdo, "encrypted_data/temperature", encryptedData, sizeof(encryptedData));

            // Write encrypted AES key to the database path
            Firebase.RTDB.setBlob(&fbdo, "encrypted_data/aes_key", encryptedAESKey, sizeof(encryptedAESKey));
        }

        Serial.println("\n-----------------------");

        Serial.println();
    } else {
        Serial.println("Failed to read valid temperature data from DHT sensor!");
    }
}