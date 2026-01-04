# Security Enhancement Issues for P2P File Transfer

This document contains individual GitHub issues for implementing security features. Copy each section as a separate issue on your repository.

---

## Issue #1: Add File Integrity Verification (SHA-256)

**Priority:** HIGH  
**Difficulty:** Easy  
**Labels:** `security`, `enhancement`, `good first issue`

### Problem
Currently, there's no way to verify if a file was corrupted during transfer or tampered with by an attacker. If network errors occur or a man-in-the-middle attacker modifies the file, the receiver has no way to detect it.

### Attack Scenario
1. User A sends `report.pdf` to User B
2. Network corruption or MITM attacker modifies some bytes
3. User B receives corrupted/tampered file
4. User B has no way to know the file is invalid

### Proposed Solution
Implement cryptographic hash verification using SHA-256:

**Sender side:**
- Calculate SHA-256 hash of the file before sending
- Include the hash in the file header
- Send file data as usual

**Receiver side:**
- Receive the hash from header
- Calculate SHA-256 hash of received file
- Compare both hashes
- Accept file only if hashes match

### Implementation Details
- Use OpenSSL's `SHA256()` function or `EVP_DigestInit/Update/Final`
- Hash should be calculated in chunks (same 16KB buffer) to handle large files
- Add hash field to the `fileinfo` struct
- Send hash as hex string in header: `File_Hash:a3b2c1d4e5f6...`

### Acceptance Criteria
- [x] SHA-256 hash calculated on sender side
- [x] Hash included in transfer header
- [x] Receiver verifies hash after complete transfer
- [x] Transfer marked as failed if hashes don't match
- [x] Works with large files (1GB+) without memory issues

### References
- [OpenSSL SHA-256 Documentation](https://www.openssl.org/docs/man3.0/man3/SHA256.html)
- [SHA-256 Tutorial](https://en.wikipedia.org/wiki/SHA-2)

---

## Issue #2: Prevent Packet Sniffing with TLS Encryption

**Priority:** CRITICAL  
**Difficulty:** Medium  
**Labels:** `security`, `encryption`, `enhancement`

### Problem
All data is currently transmitted in **plaintext** over the network. Anyone on the same WiFi network can use tools like Wireshark to capture and read:
- File names
- File contents
- All metadata

This is especially dangerous on public WiFi (coffee shops, airports, hotels).

### Attack Scenario
**WiFi Packet Sniffing:**
1. Attacker and victim are on same WiFi network
2. Attacker runs: `sudo tcpdump -i wlan0 port 9090 -w capture.pcap`
3. Victim transfers sensitive file
4. Attacker opens capture in Wireshark
5. Attacker reconstructs entire file from captured packets

### Proposed Solution
Implement TLS (Transport Layer Security) to encrypt all communication:

**Changes needed:**
- Wrap TCP sockets with TLS using OpenSSL
- Generate self-signed certificates for each peer
- Implement certificate verification to prevent MITM
- Use certificate pinning (users exchange certificate fingerprints out-of-band)

### Implementation Details

**Certificate Generation:**
```bash
# Generate private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Code changes:**
- Replace `socket()` with `SSL_CTX` setup
- Replace `send()`/`recv()` with `SSL_write()`/`SSL_read()`
- Replace `connect()` with `SSL_connect()`
- Replace `accept()` with `SSL_accept()`

**Certificate Verification:**
- Display certificate fingerprint to user
- User verifies fingerprint matches what peer shared (via phone/text)
- Reject connection if fingerprint doesn't match

### Acceptance Criteria
- [ ] TLS 1.3 or 1.2 minimum version enforced
- [ ] Self-signed certificates generated and used
- [ ] Certificate fingerprint displayed to users
- [ ] Connection rejected if certificate verification fails
- [ ] All data encrypted (verified with Wireshark showing encrypted packets)
- [ ] File transfer still works as before (backward compatibility optional)

### Libraries/Tools Needed
- OpenSSL development libraries: `sudo apt-get install libssl-dev`
- Or mbedTLS as lighter alternative

### References
- [OpenSSL SSL/TLS Programming](https://wiki.openssl.org/index.php/SSL/TLS_Client)
- [Simple TLS Server Example](https://stackoverflow.com/questions/7698488/turn-a-simple-socket-into-an-ssl-socket)

---

## Issue #3: Implement Authentication to Prevent Unauthorized Access

**Priority:** HIGH  
**Difficulty:** Medium  
**Labels:** `security`, `authentication`, `enhancement`

### Problem
Currently, **anyone** who knows the receiver's IP address can:
- Connect and send files (potentially malware)
- The receiver has no way to verify the sender's identity

Similarly, senders have no way to verify they're connecting to the legitimate receiver.

### Attack Scenarios

**Scenario 1: Malware Injection**
1. User B starts receiver on 192.168.1.100
2. Attacker on same network discovers port 9090 is open
3. Attacker connects and sends `malware.exe`
4. User B thinks it's from User A and executes it

**Scenario 2: Wrong Recipient**
1. User A wants to send to 192.168.1.100
2. User A typos: 192.168.1.101 (attacker's machine)
3. User A sends confidential document to attacker

**Scenario 3: Race Condition**
1. User B tells User A their IP
2. Attacker connects first before User A
3. Attacker receives the file meant for User B

### Proposed Solution
Implement pre-shared key authentication with challenge-response protocol:

**Setup (out-of-band):**
- Both users agree on a shared password/key (via phone call, encrypted message, etc.)
- Never transmit password in plaintext over the connection

**Authentication Flow:**
1. Connection established
2. Receiver sends random challenge (nonce)
3. Sender computes HMAC-SHA256(challenge, shared_key)
4. Sender sends HMAC response
5. Receiver verifies HMAC
6. If valid, proceed with file transfer
7. If invalid, close connection

### Implementation Details

**Data structures:**
```c
typedef struct {
    char challenge[32];  // Random bytes
    char response[64];   // HMAC-SHA256 output (hex)
} auth_message;
```

**Functions needed:**
- `generate_random_challenge()` - uses `/dev/urandom` or OpenSSL RAND
- `compute_hmac_sha256()` - uses OpenSSL HMAC functions
- `verify_hmac()` - constant-time comparison

**Protocol:**
```
Receiver -> Sender: AUTH_CHALLENGE:<random_32_bytes_hex>
Sender -> Receiver: AUTH_RESPONSE:<hmac_hex>
Receiver -> Sender: AUTH_STATUS:OK or AUTH_STATUS:FAIL
```

### Security Considerations
- Use cryptographically secure random number generator (NOT `rand()`)
- Use constant-time comparison to prevent timing attacks
- Regenerate challenge for each connection (prevent replay attacks)
- Consider adding timestamp to prevent old challenge reuse

### Acceptance Criteria
- [ ] Pre-shared key can be configured (command-line arg or config file)
- [ ] Challenge-response implemented correctly
- [ ] Uses HMAC-SHA256 for authentication
- [ ] Connection rejected if authentication fails
- [ ] No password transmitted in plaintext
- [ ] Resistant to replay attacks (nonce used)

### References
- [HMAC Wikipedia](https://en.wikipedia.org/wiki/HMAC)
- [Challenge-Response Authentication](https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication)
- [OpenSSL HMAC Functions](https://www.openssl.org/docs/man3.0/man3/HMAC.html)

---

## Issue #4: Protect Against ARP Spoofing/MITM Attacks

**Priority:** MEDIUM  
**Difficulty:** Hard  
**Labels:** `security`, `network`, `enhancement`

### Problem
Even with the correct IP address, attackers on the same local network can intercept traffic using ARP spoofing, redirecting packets to themselves at the MAC address layer.

### Attack Scenario
**ARP Spoofing:**
1. User A (192.168.1.50) wants to send file to User B (192.168.1.100)
2. Attacker runs: `arpspoof -i wlan0 -t 192.168.1.50 192.168.1.100`
3. Attacker's machine starts claiming "I'm 192.168.1.100!"
4. User A's computer updates ARP table with attacker's MAC address
5. All packets meant for User B now go to attacker
6. Attacker can read, modify, or forward packets

**Visual:**
```
Expected: User A -----> User B
Actual:   User A -----> Attacker -----> User B
                        (reads everything)
```

### Why This Bypasses IP-Based Security
- IP addresses are Layer 3 (network layer)
- ARP operates at Layer 2 (data link layer) 
- Attacker manipulates MAC address mapping
- Your application never knows packets are being redirected

### Proposed Solution
This attack cannot be prevented at the application layer alone, but can be **detected and mitigated**:

**Option 1: Certificate Pinning (Requires Issue #2 - TLS)**
- Each peer has unique certificate
- Users exchange certificate fingerprints out-of-band
- Even if MITM intercepts connection, they can't present valid certificate
- Application rejects connection if certificate doesn't match expected fingerprint

**Option 2: Static ARP Entries (User Configuration)**
- Document how users can set static ARP entries
- Prevents ARP spoofing on their machine
```bash
# Linux
sudo arp -s 192.168.1.100 AA:BB:CC:DD:EE:FF

# Add to README as security hardening guide
```

**Option 3: ARP Monitoring (Detection)**
- Monitor for ARP table changes during file transfer
- Alert user if MAC address for peer's IP changes mid-transfer
- Requires root privileges and platform-specific code

### Implementation Details

**Best approach: Combine Issue #2 (TLS) with Certificate Pinning**
```c
// Display certificate fingerprint before transfer
void display_cert_fingerprint(X509 *cert) {
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    SHA256(cert->..., fingerprint);
    printf("Certificate fingerprint: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X:", fingerprint[i]);
    }
}

// User verifies this matches what peer shared via phone/text
```

### Acceptance Criteria
- [ ] TLS with certificate pinning implemented (depends on Issue #2)
- [ ] Certificate fingerprint displayed to users
- [ ] Users can verify fingerprint matches expected value
- [ ] Connection rejected if certificate fingerprint doesn't match
- [ ] Documentation added for static ARP hardening (optional)

### References
- [ARP Spoofing Explained](https://en.wikipedia.org/wiki/ARP_spoofing)
- [Certificate Pinning Guide](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)

---

## Issue #5: Add Input Validation and Sanitization

**Priority:** HIGH  
**Difficulty:** Easy  
**Labels:** `security`, `bugfix`, `good first issue`

### Problem
The application doesn't properly validate user inputs, making it vulnerable to several attacks:

1. **Path Traversal:** Attacker sends filename like `../../../../etc/passwd`
2. **Buffer Overflow:** Filename longer than 100 chars overwrites memory
3. **Format String:** Special characters in filename could cause issues

### Attack Scenarios

**Path Traversal:**
```
Attacker sends header:
File_Name:../../../../home/victim/.ssh/id_rsa
File_Size:1234

Receiver creates file at dangerous location, potentially overwriting sensitive files
```

**Buffer Overflow:**
```c
char file_name[100];
// Attacker sends 200 character filename
sscanf(recived_header1, "File_Name:%s\n...", file_name);
// Buffer overflow! Memory corruption!
```

### Proposed Solution

**1. Sanitize Filenames:**
```c
int is_safe_filename(const char *filename) {
    // Reject if contains path separators
    if (strchr(filename, '/') || strchr(filename, '\\')) {
        return 0;
    }
    // Reject if contains parent directory reference
    if (strstr(filename, "..")) {
        return 0;
    }
    // Reject if starts with dot (hidden files)
    if (filename[0] == '.') {
        return 0;
    }
    // Check length
    if (strlen(filename) >= 100) {
        return 0;
    }
    return 1;
}
```

**2. Use Safe String Functions:**
```c
// BEFORE (dangerous):
sscanf(recived_header1, "File_Name:%s\n...", file_name);

// AFTER (safe):
char temp[256];
if (sscanf(recived_header1, "File_Name:%255s\n...", temp) == 1) {
    if (is_safe_filename(temp) && strlen(temp) < sizeof(file_name)) {
        strncpy(file_name, temp, sizeof(file_name) - 1);
        file_name[sizeof(file_name) - 1] = '\0';
    } else {
        // Reject dangerous filename
    }
}
```

**3. Validate File Size:**
```c
#define MAX_FILE_SIZE (10ULL * 1024 * 1024 * 1024)  // 10GB limit

if (file_size == 0 || file_size > MAX_FILE_SIZE) {
    fprintf(stderr, "Invalid file size\n");
    return;
}
```

**4. Validate IP Address:**
```c
int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}
```

### Implementation Checklist
- [ ] Sanitize filename (reject path separators and `..`)
- [ ] Use bounded string operations (`strncpy`, `snprintf`)
- [ ] Validate file size (min and max limits)
- [ ] Validate IP address format
- [ ] Check buffer sizes before any copy operation
- [ ] Add maximum filename length check
- [ ] Reject hidden files (starting with `.`) optional
- [ ] Add unit tests for validation functions

### Acceptance Criteria
- [ ] Path traversal attacks prevented
- [ ] Buffer overflow vulnerabilities fixed
- [ ] All user inputs validated before use
- [ ] Error messages shown for invalid inputs
- [ ] No crashes with malicious inputs

### References
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-120: Buffer Overflow](https://cwe.mitre.org/data/definitions/120.html)

---

## Issue #6: Implement End-to-End File Encryption

**Priority:** MEDIUM  
**Difficulty:** Hard  
**Labels:** `security`, `encryption`, `enhancement`

### Problem
Even with TLS (Issue #2), there are scenarios where file contents could be exposed:
- If TLS is compromised (weak ciphers, implementation bugs)
- If someone has access to receiver's disk before user opens file
- Compliance requirements for data-at-rest encryption

Additionally, TLS only protects data in transit. The file is stored unencrypted on the receiver's disk.

### Proposed Solution
Implement end-to-end encryption where the file is encrypted **before** transmission:

**Flow:**
1. Sender encrypts file with AES-256-GCM
2. Sender transmits encrypted file chunks (TLS is additional layer)
3. Receiver stores encrypted file
4. Receiver decrypts file after verification

**Key Exchange Options:**

**Option A: Pre-Shared Key (Simpler)**
- Both users share a password out-of-band
- Derive encryption key using PBKDF2 or Argon2
- Use same key for encryption/decryption

**Option B: Diffie-Hellman (More Secure)**
- Each peer generates ephemeral key pair
- Exchange public keys
- Derive shared secret
- No pre-shared password needed

### Implementation Details

**Encryption:**
```c
// Use AES-256-GCM for authenticated encryption
// Provides both confidentiality and integrity

typedef struct {
    unsigned char key[32];        // 256-bit key
    unsigned char iv[12];         // 96-bit IV for GCM
    unsigned char tag[16];        // 128-bit authentication tag
} encryption_params;

// Encrypt file in chunks
int encrypt_chunk(unsigned char *plaintext, size_t len,
                  encryption_params *params,
                  unsigned char *ciphertext);
```

**Key Derivation from Password:**
```c
// Use PBKDF2 to derive key from password
int derive_key_from_password(const char *password,
                             unsigned char *salt,
                             unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                             salt, 16,
                             100000,  // iterations
                             EVP_sha256(),
                             32, key);
}
```

### Protocol Changes

**New Header Fields:**
```
File_Name:example.txt.enc  (add .enc extension)
File_Size:1234             (size of encrypted data)
Encryption:AES-256-GCM
IV:<96_bit_iv_hex>
Salt:<128_bit_salt_hex>
Auth_Tag:<128_bit_tag_hex>  (sent after file data)
```

### Security Considerations
- Never reuse IV (generate random IV for each file)
- Use authenticated encryption (GCM mode) to prevent tampering
- Derive key properly (use PBKDF2/Argon2, not plain password)
- Use secure random number generator for IV and salt
- Consider adding key confirmation to detect wrong password

### Acceptance Criteria
- [ ] AES-256-GCM encryption implemented
- [ ] Key derived securely from password (PBKDF2/Argon2)
- [ ] Random IV generated for each transfer
- [ ] Authentication tag verified on receiver side
- [ ] Encrypted files can be decrypted correctly
- [ ] Wrong password detected before writing file
- [ ] Works with large files (encrypt in chunks)

### Optional Enhancements
- [ ] Implement Diffie-Hellman key exchange
- [ ] Add option to delete encrypted file after decryption
- [ ] Compress before encrypting (optional)

### References
- [AES-GCM Encryption](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [OpenSSL EVP Encryption](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
- [PBKDF2 Key Derivation](https://en.wikipedia.org/wiki/PBKDF2)

---

## Issue #7: Add Connection Rate Limiting and DoS Protection

**Priority:** MEDIUM  
**Difficulty:** Medium  
**Labels:** `security`, `performance`, `enhancement`

### Problem
The receiver currently has no protection against:
- **Connection flooding:** Attacker opens hundreds of connections
- **Resource exhaustion:** Attacker sends massive files to fill disk
- **Slowloris-style attacks:** Attacker sends data very slowly to tie up resources

### Attack Scenarios

**Connection Flooding:**
```bash
# Attacker script
while true; do
    nc 192.168.1.100 9090 &
done
# Opens thousands of connections, crashes receiver
```

**Disk Space Exhaustion:**
```
Attacker sends header:
File_Size:999999999999999  (999TB)

Receiver attempts to write, fills entire disk
```

**Slow Transfer Attack:**
```
Attacker connects, sends 1 byte every 10 seconds
Receiver keeps connection open indefinitely
```

### Proposed Solution

**1. Connection Rate Limiting:**
```c
#define MAX_CONNECTIONS_PER_IP 3
#define RATE_LIMIT_WINDOW 60  // seconds

typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t last_connection;
    int connection_count;
} rate_limit_entry;

// Check if IP is allowed to connect
int check_rate_limit(const char *client_ip);
```

**2. Maximum File Size Limit:**
```c
#define MAX_FILE_SIZE (10ULL * 1024 * 1024 * 1024)  // 10GB

if (file_size > MAX_FILE_SIZE) {
    send_error(clientfd, "File too large");
    close(clientfd);
    return;
}
```

**3. Connection Timeout:**
```c
// Set socket timeout
struct timeval timeout;
timeout.tv_sec = 30;  // 30 second timeout
timeout.tv_usec = 0;

setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO,
           &timeout, sizeof(timeout));
```

**4. Disk Space Check:**
```c
#include <sys/statvfs.h>

int check_disk_space(const char *path, uint64_t required_bytes) {
    struct statvfs stat;
    if (statvfs(path, &stat) != 0) {
        return 0;
    }
    uint64_t available = stat.f_bavail * stat.f_frsize;
    return available > required_bytes;
}
```

### Implementation Details

**Rate Limiting Structure:**
- Maintain list of recent connections with IP and timestamp
- Cleanup entries older than rate limit window
- Reject new connections if IP exceeds limit

**Timeout Handling:**
- Set SO_RCVTIMEO and SO_SNDTIMEO socket options
- Close connection if no data received within timeout
- Display timeout error to user

**Resource Limits:**
- Check available disk space before accepting file
- Enforce maximum file size
- Limit concurrent connections

### Acceptance Criteria
- [ ] Maximum 3 connections per IP per minute (configurable)
- [ ] Connection timeout after 30 seconds of inactivity
- [ ] Maximum file size enforced (10GB default, configurable)
- [ ] Disk space checked before accepting file
- [ ] Graceful error messages for rejected connections
- [ ] Rate limit entries cleaned up properly

### Configuration
Add command-line options:
```bash
./p2p_transfer --max-file-size 5G
./p2p_transfer --connection-tim
