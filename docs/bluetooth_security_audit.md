# PebbleOS Bluetooth Communication Security Audit

**Date:** 2026-03-06
**Scope:** PebbleOS firmware Bluetooth communication stack
**Methodology:** Static code analysis of the PebbleOS source code

---

## Executive Summary

PebbleOS relies **entirely** on BLE link-layer encryption (via LE Secure Connections
with Numeric Comparison) for confidentiality and integrity of all data in transit.
There is **no application-layer encryption** within the Pebble Protocol itself. This
means the security of all sensitive data — notifications, voice, health data,
contacts, calendar events, and firmware updates — depends solely on the strength of
the BLE pairing and the BLE link encryption.

The good news: the BLE pairing configuration is strong (SC-only, MITM-protected,
Numeric Comparison). The bad news: there are several attack surfaces that could be
exploited depending on the scenario, and there is no defense-in-depth above the
link layer.

---

## 1. BLE Pairing & Encryption Configuration

### What the firmware configures

The NimBLE stack is configured with these Security Manager (SM) settings, consistent
across both nrf52 and sf32lb52 targets:

| Setting | Value | Meaning |
|---------|-------|---------|
| `BLE_SM_SC` | 1 | LE Secure Connections enabled |
| `BLE_SM_SC_ONLY` | 1 | **Only** Secure Connections accepted (legacy pairing rejected) |
| `BLE_SM_LEGACY` | 0 | Legacy pairing disabled |
| `BLE_SM_MITM` | 1 | MITM protection required |
| `BLE_SM_IO_CAP` | `BLE_HS_IO_DISPLAY_YESNO` | Numeric Comparison pairing |
| `BLE_SM_BONDING` | 1 | Bonding enabled (keys stored) |
| `BLE_SM_LVL` | 4 | Security level 4 (authenticated LE Secure Connections) |
| `BLE_SM_SC_DEBUG_KEYS` | 0 | Debug keys disabled |
| `BLE_SM_OUR_KEY_DIST` | 1 | Distribute EncKey (LTK) |
| `BLE_SM_THEIR_KEY_DIST` | 3 | Receive EncKey + IdKey (LTK + IRK) |
| `BLE_RPA_TIMEOUT` | 300 | RPA rotation every 5 minutes |

**Source files:**
- `third_party/nimble/syscfg/targets/nrf52/syscfg.yml:11-15`
- `third_party/nimble/syscfg/targets/sf32lb52/syscfg.yml:6-10`
- `third_party/nimble/syscfg/app/syscfg.yml:6-9`
- `third_party/nimble/port/include/sf32lb52/syscfg/syscfg.h:880-941`

### Assessment

**STRONG**: This is a best-practice BLE security configuration:
- SC-Only mode prevents downgrade to legacy pairing (vulnerable to passive
  eavesdropping via ECDH cracking of the short TK)
- Numeric Comparison provides MITM protection during pairing
- Security Level 4 is the highest BLE security level
- Debug keys are disabled (prevents trivial key extraction)
- IRK distribution enables Resolvable Private Addresses for tracking resistance

---

## 2. Pebble Protocol Layer — No Application-Layer Encryption

### Finding: CRITICAL ARCHITECTURE DECISION

The Pebble Protocol header contains only length and endpoint ID — no encryption,
MAC, nonce, or session token fields:

```c
// src/fw/services/common/comm_session/protocol.h:9-12
typedef struct PACKED {
  uint16_t length;
  uint16_t endpoint_id;
} PebbleProtocolHeader;
```

A search for encryption/cipher/AES/HMAC/signing/signature across the entire
`src/fw/services/common/comm_session/` directory returns **zero results**.

The CommSession capability negotiation (`session.h:33-51`) includes flags for music,
notifications, language packs, voice, weather, etc. — but **no encryption or
authentication capability**.

**Impact:** All data confidentiality and integrity relies solely on BLE link-layer
encryption. If the link-layer is compromised, all data is exposed in cleartext.

---

## 3. Threat Analysis: Passive Sniffing

### 3.1 Against a paired, bonded connection

**Difficulty: VERY HARD (effectively infeasible with current technology)**

When the watch is paired and bonded with the phone using LE Secure Connections:
- The link is encrypted with AES-CCM using a 128-bit Long Term Key (LTK)
- The LTK is derived via ECDH key exchange (P-256 curve) during pairing
- Passive sniffing of the encrypted link reveals nothing useful
- Even capturing the entire pairing exchange doesn't help — ECDH prevents
  passive key recovery
- RPA rotation every 5 minutes (`BLE_RPA_TIMEOUT=300`) provides some tracking
  resistance

**What an attacker learns from passive sniffing:**
- Timing and volume of BLE packets (traffic analysis)
- BLE advertisement data (device name, service UUIDs) when advertising
- Connection intervals and parameters
- That a Pebble device is present in the area

**What they CANNOT learn:**
- Notification contents
- Health data
- Voice/audio data
- Any Pebble Protocol payload

### 3.2 Against an unencrypted connection (pre-pairing or pairing failure)

The firmware code shows that connections can exist in an unencrypted state:

```c
// src/fw/comm/ble/gap_le_connect.c:115-116
GAPLEConnectionEventConnectedNotEncrypted,
GAPLEConnectionEventConnectedAndEncrypted,
```

The code at `gap_le_connect.c:429-430` shows clients can receive a
`ConnectedNotEncrypted` event. However, PPoGATT (the data transport) appears to
require pairing before data exchange begins — the `is_pairing_required` flag
controls whether the connection event is held until encryption is established
(`gap_le_connect.c:66-79`).

**Risk:** If there is any window where Pebble Protocol data flows before encryption
is fully established, a passive sniffer could capture it. The code has TODO comments
suggesting the pairing-before-data flow may not be fully enforced in all paths
(`gap_le_connect.c:437-438: "TODO: kick off pairing"`).

---

## 4. Threat Analysis: Active MITM Attack

### 4.1 Against initial pairing (first-time setup)

**Difficulty: HARD but theoretically possible via social engineering**

The pairing uses Numeric Comparison, which requires user confirmation of a
6-digit number on both devices. An active MITM attacker would need to:

1. Jam the legitimate connection
2. Pair with both the watch and the phone separately
3. Display matching 6-digit codes to the user on both sides

This is **prevented** by Numeric Comparison — the attacker cannot force the same
code on both sides (the codes are cryptographically derived from the ECDH exchange).
The user would see different codes and should reject.

**Vulnerability:** If the user blindly confirms without comparing codes, the MITM
succeeds. This is a human factors issue, not a protocol issue.

### 4.2 Against an established bonded connection

**Difficulty: EFFECTIVELY IMPOSSIBLE**

Once bonded, the LTK is stored on both devices. Reconnection uses the LTK directly
(no new ECDH exchange needed for an active MITM to intercept). An attacker cannot
insert themselves into an established bond.

### 4.3 Re-pairing attack

The firmware handles repeat pairing (`advert.c:274-289`):

```c
// src/bluetooth-fw/nimble/advert.c:274-279
// In main firmware, only allow repeat pairing if using secure connections
// and we support user confirmation.
#if defined(RECOVERY_FW) || \
    (MYNEWT_VAL(BLE_SM_SC_ONLY) && (MYNEWT_VAL(BLE_SM_IO_CAP) == BLE_HS_IO_DISPLAY_YESNO))
```

Repeat pairing deletes the old bond and re-pairs. This requires user confirmation
(Numeric Comparison), so it's protected against MITM.

**Recovery firmware exception:** In `RECOVERY_FW` mode, repeat pairing is
unconditionally allowed. If an attacker can force the watch into recovery mode,
pairing security may be weaker.

### 4.4 What a successful MITM could do

If an attacker somehow established a MITM position (e.g., user error during
pairing), they would have **complete access** to all Pebble Protocol traffic because
there is no application-layer encryption or authentication. They could:

| Capability | Details |
|-----------|---------|
| **Read notifications** | SMS, email, call info — all plaintext over Pebble Protocol (endpoint 0x0021, ANCS) |
| **Read health data** | Steps, heart rate, sleep data via data logging endpoint 0x1a7a |
| **Intercept voice/audio** | Audio frames sent plaintext via endpoint 10000 |
| **Read contacts & calendar** | Synced via BlobDB endpoints 0xb1db/0xb2db |
| **Read AppMessage data** | Third-party app data via endpoint 0x0030 |
| **Send fake notifications** | Inject notification push messages |
| **Push malicious firmware** | Via PutBytes endpoint 0xbeef (see Section 6) |
| **Send factory reset** | Via reset endpoint 0x07d3 (private but no auth beyond session type) |
| **Dump device logs** | Via dump_log endpoint 0x07d2 |
| **Control music playback** | Via music endpoint 0x0020 |
| **Manipulate timeline** | Add/remove/modify calendar events, reminders |

---

## 5. Threat Analysis: Phone Out of Range

### Scenario: Watch is alone (phone not present)

When the phone is out of range:

1. **The watch advertises** to allow reconnection. Advertisement packets reveal:
   - Device name (depending on advertising data configuration)
   - Pebble-specific service UUIDs (identifying it as a Pebble)
   - The watch's BLE address (RPA rotates every 5 minutes)

2. **An attacker cannot establish a Pebble Protocol session** because:
   - The watch will only accept connections from a bonded device (using the stored LTK)
   - The attacker would need to pair, which requires Numeric Comparison user confirmation
   - Without a valid LTK, the watch won't proceed to PPoGATT data exchange

3. **However, the attacker COULD:**
   - **Track the watch** via BLE advertisements (mitigated by RPA rotation)
   - **Attempt a BLE connection** to probe the watch's GATT services
   - **Read unprotected GATT characteristics** — the Pebble Pairing Service
     characteristics do NOT require encryption at the GATT level:
     ```c
     // src/bluetooth-fw/nimble/pebble_pairing_service.c:120
     .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,  // No _ENC flag!
     // src/bluetooth-fw/nimble/pebble_pairing_service.c:126
     .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,   // No _ENC flag!
     ```
     This allows any connected device to read the connectivity status without encryption.
   - **Write to the trigger-pairing characteristic** — while the handler does check
     encryption state internally (`pebble_pairing_service.c:82,97`), the GATT-level
     permission allows the write to reach the handler.
   - **Attempt DoS** by flooding connection requests

4. **GH3X2X tuning service** (health sensor) also lacks encryption flags:
   ```c
   // src/bluetooth-fw/nimble/gh3x2x_tuning_service.c:49,53
   .flags = BLE_GATT_CHR_F_NOTIFY,
   .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,  // No _ENC!
   ```
   An unauthenticated device could potentially write to the health sensor tuning
   characteristic.

---

## 6. Firmware & App Installation (PutBytes) — No Code Signing

### Finding: HIGH SEVERITY

The PutBytes mechanism (`src/fw/services/common/put_bytes/`) handles installation of:
- Firmware updates
- Watch apps
- Watch faces
- Language packs
- Other binary objects

**No signature verification** was found in the PutBytes code path. The only integrity
check is a CRC provided by the sender:

```c
// src/fw/services/common/put_bytes/put_bytes.c (CommitRequest)
uint32_t crc;  // CRC provided by the SENDER, not independently verified
```

The CRC protects against accidental corruption but provides **zero security** against
a malicious actor who can compute the correct CRC for their malicious payload.

**Impact:** If an attacker achieves a MITM position or can otherwise send Pebble
Protocol messages, they could push arbitrary firmware or applications to the watch
with no signature check preventing execution.

---

## 7. Connection Parameter Manipulation

### Finding: MEDIUM SEVERITY

The connection update request handler blindly accepts peer-requested parameters:

```c
// src/bluetooth-fw/nimble/advert.c:170-171
static void prv_handle_conn_update_req_event(struct ble_gap_event *event) {
  *event->conn_update_req.self_params = *event->conn_update_req.peer_params;
```

No validation is performed on:
- Connection interval (could be set very fast, draining battery)
- Slave latency (could be set to 0, preventing power savings)
- Supervision timeout (could be set very short, causing disconnections)

**Impact:** A connected device (the bonded phone, or a MITM) could manipulate
connection parameters to drain the watch battery faster or cause instability.

---

## 8. GATT Service Exposure Without Encryption Requirements

### Finding: MEDIUM SEVERITY

Several GATT services expose characteristics without requiring encryption at the
GATT permission level:

1. **Pebble Pairing Service** (`pebble_pairing_service.c:111-137`):
   - Connection Status: `BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY` (no encryption)
   - Trigger Pairing: `BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE` (no encryption)

2. **GH3X2X Health Sensor Tuning** (`gh3x2x_tuning_service.c:39-53`):
   - RX: `BLE_GATT_CHR_F_NOTIFY` (no encryption)
   - TX: `BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP` (no encryption)

3. **Device Information Service** (`syscfg.yml: BLE_SVC_DIS_DEFAULT_READ_PERM: 0`):
   - Read permission 0 = no security requirement

**Recommendation:** Add `BLE_GATT_CHR_F_READ_ENC` and `BLE_GATT_CHR_F_WRITE_ENC`
flags to enforce encryption at the GATT level, providing defense-in-depth.

---

## 9. Endpoint Access Control

The Pebble Protocol has a basic access control system distinguishing "private"
(system app only) and "any" (3rd party apps too) endpoints. From
`protocol_endpoints_table.json`:

| Access | Endpoints | Risk |
|--------|-----------|------|
| **any** | AppMessage (0x30), Ping (0x7d1), Meta (0x0000), Version (0x10,0x11), Launcher (0x31), App Config (0x32), Comm Poll (0xcafe) | Third-party apps can use these |
| **private** | Notifications, Music, Phone, Audio, Health, BlobDB, PutBytes, Reset, Factory, Screenshot, Logs | System app only |

**Note:** "Private" only means the endpoint is restricted to the system session
(Pebble companion app). It does **not** imply any cryptographic authentication.
If an attacker compromises the companion app or performs a MITM, all "private"
endpoints are accessible.

---

## 10. Additional Attack Vectors

### 10.1 Bluetooth Classic (SPP) — Not present in current codebase

No SPP/RFCOMM implementation was found in the current NimBLE-based Bluetooth
firmware. The architecture supports it as a transport type (mentioned in session.h),
but the current codebase appears BLE-only. Classic Bluetooth, when present, would
have its own pairing and security concerns.

### 10.2 BLE Advertisement Tracking

- RPA rotation every 300 seconds provides moderate tracking resistance
- During the 5-minute window, a device can be tracked
- Advertisement data may include identifying service UUIDs
- The `ble_hs_id_infer_auto()` call (`advert.c:382`) may select public address
  if no IRK is available, eliminating tracking protection

### 10.3 Side-Channel: Traffic Analysis

Even with encryption, an attacker can observe:
- **Timing patterns** — when notifications arrive (correlate with known events)
- **Packet sizes** — different endpoint payloads have different sizes
- **Connection events** — phone calls cause specific traffic patterns
- **Health sync patterns** — periodic data logging uploads are predictable

### 10.4 Denial of Service

- **BLE jamming** — standard radio-level attack, no software mitigation possible
- **Connection flooding** — repeated connection attempts to drain battery
- **Connection parameter manipulation** — as described in Section 7
- **Malformed PPoGATT packets** — could potentially crash the PPoGATT state machine

### 10.5 Key Extraction from Watch Hardware

If an attacker has physical access to the watch:
- The bonding keys (LTK, IRK) are stored in persistent storage
  (`bluetooth_persistent_storage.c`)
- If flash storage is not encrypted, keys could be extracted via JTAG/SWD
- This would allow passive decryption of all future (and recorded past)
  communications with the bonded phone

### 10.6 Companion App Compromise

The Pebble Protocol has no mechanism to authenticate the companion app beyond
BLE pairing. A malicious app on the phone that can access the BLE connection
could send arbitrary Pebble Protocol messages to any endpoint.

---

## 11. Summary of Findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | BLE pairing uses SC-Only + Numeric Comparison + MITM protection | GOOD | Configured correctly |
| 2 | No application-layer encryption in Pebble Protocol | HIGH | By design — relies on BLE |
| 3 | No code signing for firmware/app installation (PutBytes) | HIGH | No signature verification |
| 4 | GATT characteristics lack encryption permission flags | MEDIUM | Missing `_ENC` flags |
| 5 | Connection parameters accepted without validation | MEDIUM | No bounds checking |
| 6 | GH3X2X tuning service writable without auth | MEDIUM | Missing `_ENC` flags |
| 7 | Bonding keys stored without at-rest encryption | LOW-MEDIUM | Physical access required |
| 8 | Recovery FW allows unconditional re-pairing | LOW | Requires recovery mode entry |
| 9 | Traffic analysis possible despite encryption | LOW | Inherent to BLE |
| 10 | No defense-in-depth above link layer | ARCHITECTURAL | Single point of failure |

---

## 12. Recommendations

### High Priority

1. **Add application-layer encryption/authentication** to the Pebble Protocol or at
   minimum to sensitive endpoints (notifications, voice, health, PutBytes). This
   provides defense-in-depth if the BLE link is compromised.

2. **Implement code signing** for firmware updates and app installation. The PutBytes
   mechanism should verify a cryptographic signature before committing any binary.

3. **Add `BLE_GATT_CHR_F_READ_ENC` / `BLE_GATT_CHR_F_WRITE_ENC`** flags to all
   GATT characteristics that handle sensitive data, including the Pebble Pairing
   Service and GH3X2X tuning service.

### Medium Priority

4. **Validate connection parameter update requests** — add bounds checking to reject
   parameters outside acceptable ranges in `prv_handle_conn_update_req_event()`.

5. **Add session-level authentication tokens** — after BLE pairing, establish a
   session key or token that must be presented for sensitive operations.

6. **Encrypt bonding keys at rest** — use platform hardware security features
   (if available) to protect stored LTK/IRK.

### Low Priority

7. **Reduce RPA rotation interval** — consider shorter intervals than 300 seconds
   for improved tracking resistance.

8. **Add rate limiting** for connection attempts and GATT operations to mitigate DoS.

9. **Audit PPoGATT state machine** for resilience against malformed packet sequences
   that could cause crashes or undefined behavior.

---

## 13. Answers to Specific Questions

### Q: If a victim has a Pebble device setup, what could a nearby adversary do?

A passive nearby adversary can determine a Pebble device is present (via BLE
advertisements) and track it within 5-minute RPA rotation windows. They cannot
read any data from the encrypted BLE link.

### Q: If they sniff packets, what can they learn? (Passive MITM)

With LE Secure Connections, passive sniffing reveals only metadata: packet timing,
sizes, and connection parameters. All payload data is AES-CCM encrypted. The
attacker **cannot** recover the encryption key from passive observation of either
the pairing or the data exchange.

### Q: What if they perform an active MITM?

An active MITM during initial pairing is prevented by Numeric Comparison — the
user must confirm matching 6-digit codes. If the user doesn't verify the codes,
the MITM succeeds and gives the attacker **full access** to all watch data and
the ability to push malicious firmware (no code signing). Against an established
bond, active MITM is effectively impossible.

### Q: Can the attacker read information from the watch?

Not without breaking the BLE encryption or compromising the pairing. If they
achieve a MITM position, they can read everything: notifications (SMS, email,
calls), health data, contacts, calendar, app data, and voice audio.

### Q: Could they see, send, or reply to notifications or hear voice data?

Only with a successful MITM. All notification content, voice audio frames, and
phone call information flow as plaintext within the encrypted BLE link. A MITM
attacker could read all notifications, inject fake ones, and intercept voice data.

### Q: Could they influence the Pebble device in any way?

With a successful MITM: yes, they could push malicious firmware, trigger factory
reset, dump logs, control music, and manipulate the timeline. Without a MITM:
they could potentially write to unprotected GATT characteristics (GH3X2X tuning)
and read the pairing service status.

### Q: What if the phone is out of range?

The watch continues advertising. An attacker cannot establish a Pebble Protocol
session without pairing (requires user confirmation). However, they can probe
GATT services and potentially write to unprotected characteristics. They cannot
access any watch data stored on the device via Bluetooth.

### Q: Is there encryption or mutual authentication?

**Encryption:** Yes, at the BLE link layer (AES-CCM via LE Secure Connections).
No encryption at the Pebble Protocol application layer.

**Mutual authentication:** Yes, via BLE Secure Connections pairing with Numeric
Comparison. Both devices confirm the same 6-digit code. After bonding, mutual
authentication is implicit via the shared LTK. No additional application-layer
authentication exists.

### Q: Are there other attacks to consider?

- Physical key extraction (JTAG/SWD access to read stored bonding keys)
- Companion app compromise (malicious app on the phone)
- BLE jamming / DoS attacks
- Traffic analysis (timing/size correlation even with encryption)
- Recovery firmware downgrade (weaker pairing in recovery mode)
- Connection parameter manipulation (battery drain)
- Malformed PPoGATT packet injection (potential crashes)
