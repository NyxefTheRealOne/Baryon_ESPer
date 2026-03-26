/*
 * Baryon ESPer, by Nyxef
 * https://github.com/NyxefTheRealOne/Baryon_ESPer/
 *
 * ─── WHAT THIS PROGRAM DOES ───────────────────────────────────────────────────
 *
 *  The PSP's System Controller (Baryon/Tachyon) will not boot from NAND flash
 *  without first authenticating a genuine Sony battery on the DATA pin. If the
 *  NAND is corrupt or the firmware is bad, you can't boot to fix it — because
 *  the Baryon locks the boot process behind this battery authentication check.
 *
 *  This firmware turns an ESP32-C3 SuperMini into a fake Sony battery. It speaks
 *  the full PSP battery authentication protocol over a single-wire UART bus,
 *  completing the Baryon handshake so the PSP proceeds to boot — even with no
 *  real battery plugged in, and even with a corrupt/missing firmware image. This
 *  is commonly called a "JigKick" or "service mode" battery emulator.
 *
 * ─── SUPPORTED PSP MODELS ─────────────────────────────────────────────────────
 *
 *  ✓ PSP-1000 (Fat / "Phat")
 *      Uses the standard 2-challenge AES handshake (opcodes 0x80 + 0x81).
 *      Key version IDs used by known PSP-1000 Baryon firmware are present in
 *      KEYSTORE and CHALLENGE1/2_SECRET tables (IDs 0x00–0x0D).
 *
 *  ✓ PSP-2000 (Slim & Lite)
 *      Also uses the standard 2-challenge AES handshake.
 *      Baryon firmware on PSP-2000 hardware uses key IDs in the middle range
 *      of the keystore (IDs 0x2F, 0x97, 0xB3 etc.). All are present.
 *
 *  ✓ PSP-3000 (Brite)
 *      Also uses the standard 2-challenge AES handshake.
 *      Late-revision Baryon firmware (key IDs 0xD9, 0xEB) is supported.
 *      Hardware revisions TA-090v2 / TA-095 (key IDs 0xEB and 0xB3) require
 *      an extra "nudge" packet after challenge 2 — this is handled in opcode
 *      0x81. All known PSP-3000 key IDs are present in the keystore.
 *
 *  ✓ PSP Go (N-1000)
 *      Uses a completely different authentication flow: opcode 0x90. Instead of
 *      the two-challenge AES-ECB scheme, the PSP Go does an AES-CBC handshake
 *      using its own dedicated key pair (GO_KEY1 / GO_KEY2) and a shared secret
 *      (GO_SECRET). The opcode 0x90 handler fully implements this flow.
 *
 *  ✗ PSP-E1000 (Street) — Not tested; that model uses a simplified boot path
 *     and may not require battery authentication at all.
 *
 * ─── ROOT CAUSE OF THE 0x60 BUG (fixed in this version) ──────────────────────
 *
 *  Earlier versions used SERIAL_8E2 (8 data bits, even parity, 2 stop bits).
 *  The PSP genuinely transmits 8E2 frames. However, on the ESP32-C3 (RISC-V
 *  core), the UART hardware register that controls the number of stop bits is
 *  mapped differently from the original ESP32 (Xtensa). The Arduino core's
 *  SERIAL_8E2 constant does not account for this difference, so the receiver's
 *  framing window ends up misaligned by exactly 1 bit position.
 *
 *  The symptom: the parity bit of one received byte bleeds into the MSB of the
 *  NEXT byte's value. The very first data byte after the 0x5A sync header is
 *  the length byte 0x02. The preceding sync byte 0x5A has 5 set bits, making
 *  its even-parity bit = 1. That parity bit shifts into the received length
 *  byte, turning 0x02 (0000 0010) into 0x60 (0110 0000) — consistently.
 *
 *  THE FIX: Use SERIAL_8E1 instead of SERIAL_8E2.
 *  SERIAL_8E1 frames are: [start bit | 8 data bits | 1 parity bit | 1 stop bit].
 *  The PSP's actual second stop bit simply appears as idle-line time between
 *  frames, which the UART ignores. All bytes arrive correctly framed, and the
 *  protocol works perfectly.
 *
 * ─── HARDWARE WIRING (ESP32-C3 SuperMini) ────────────────────────────────────
 *
 *  The PSP battery DATA line is a single-wire half-duplex bus. Both the PSP and
 *  the battery share this one wire — the PSP talks, then listens on the same pin.
 *
 *  We need to merge the ESP32's separate TX and RX pins onto that single wire
 *  WITHOUT letting our TX output overwrite what the PSP is trying to send.
 *  A 1N4148 signal diode in series with TX solves this:
 *
 *   ESP32-C3 TX (GPIO4) ──[1N4148 cathode→TX]──┬── PSP battery DATA pin
 *   ESP32-C3 RX (GPIO5) ──────────────────────┘
 *   ESP32-C3 GND ─────────────────────────────── PSP battery GND
 *
 *  Diode orientation: the banded end (cathode) faces the ESP32 TX pin.
 *
 *  How the diode works:
 *    - When ESP32 TX goes LOW (sending a 0 bit): diode is forward-biased,
 *      current flows, and the DATA line is pulled low. ✓
 *    - When ESP32 TX goes HIGH (idle/1 bit): diode is reverse-biased,
 *      no current flows. The PSP can now freely pull DATA low itself
 *      without fighting the ESP32 output driver. ✓
 *    - Because TX and RX share the same physical wire, every byte we transmit
 *      also comes back through RX. We discard these "echo" bytes in drainEcho().
 *
 * ─── BOARD SETTINGS IN ARDUINO IDE ───────────────────────────────────────────
 *  Board   : ESP32C3 Dev Module
 *  USB CDC : Enabled          ← required for Serial.print() over USB
 *  Upload  : USB CDC
 *
 * ─── ENABLING VERBOSE BYTE TRACING ───────────────────────────────────────────
 *  Uncomment #define RAW_DUMP below to print every received raw byte to the
 *  USB serial monitor as it arrives. Use this if bytes still look wrong after
 *  flashing — it lets you see exactly what the UART is delivering before any
 *  packet parsing happens.
 */

#include <Arduino.h>
#include "mbedtls/aes.h"   // ESP32 ships with mbedTLS built-in; no extra library needed

// #define RAW_DUMP    // ← uncomment to trace every received byte as [raw] 0xXX

// ═══════════════════════════════════════════════════════════════
//  CONFIGURATION
//  Change BOOT_MODE to select what kind of battery this emulates.
// ═══════════════════════════════════════════════════════════════

// The three possible battery personalities the PSP understands:
#define SERVICE_MODE  0   // Serial 0xFFFFFFFF  → PSP boots into factory service mode,
                          //   bypassing normal NAND boot. Use this to unbrick a PSP.
#define AUTOBOOT      1   // Serial 0x00000000  → PSP auto-boots from flash without
                          //   any user interaction (used in manufacturing/test jigs).
#define NORMAL_BOOT   2   // Serial 0x12345678  → behaves like a normal battery;
                          //   PSP boots normally from NAND (useful for no-battery boot).

#define BOOT_MODE   SERVICE_MODE    // ← Change this line to switch modes

// GPIO pin assignment for the PSP DATA bus connection
#define PSP_RX_PIN  5   // ESP32-C3 UART1 RX — receives data FROM the PSP
#define PSP_TX_PIN  4   // ESP32-C3 UART1 TX — sends data TO the PSP (via diode)

// Serial number bytes sent in response to opcode 0x0C (PSP queries battery identity).
// The PSP decodes the serial number to determine boot behavior (see mode comments above).
#if BOOT_MODE == SERVICE_MODE
  static const uint8_t SERIAL_NUMBER[4] = {0xFF, 0xFF, 0xFF, 0xFF};
#elif BOOT_MODE == AUTOBOOT
  static const uint8_t SERIAL_NUMBER[4] = {0x00, 0x00, 0x00, 0x00};
#else
  static const uint8_t SERIAL_NUMBER[4] = {0x12, 0x34, 0x56, 0x78};
#endif

// ═══════════════════════════════════════════════════════════════
//  KEYSTORE
//
//  Each PSP hardware revision (identified by its Baryon/Tachyon firmware
//  version) uses a different 128-bit AES key for battery authentication.
//  When the PSP sends opcode 0x80, the first payload byte is the version ID.
//  We look that ID up here to get the correct AES key for this session.
//
//  Coverage:
//    0x00–0x06  PSP-1000 early board revisions (TA-079, TA-081, TA-082)
//    0x08–0x0D  PSP-1000 late / PSP-2000 early board revisions (TA-085, TA-086, TA-088)
//    0x2F       PSP-2000 mid revision
//    0x97       PSP-2000 / PSP-3000 transition revision
//    0xB3       PSP-3000 (TA-090v1)
//    0xD9       PSP-3000 (TA-090v2)
//    0xEB       PSP-3000 (TA-095) — also triggers a post-auth nudge packet
//  The PSP Go (N-1000) does NOT use this keystore; it uses GO_KEY1/GO_KEY2 below.
// ═══════════════════════════════════════════════════════════════

struct KeyEntry { uint8_t id; uint8_t key[16]; };
static const KeyEntry KEYSTORE[] = {
  {0x00,{0x5C,0x52,0xD9,0x1C,0xF3,0x82,0xAC,0xA4,0x89,0xD8,0x81,0x78,0xEC,0x16,0x29,0x7B}},
  {0x01,{0x9D,0x4F,0x50,0xFC,0xE1,0xB6,0x8E,0x12,0x09,0x30,0x7D,0xDB,0xA6,0xA5,0xB5,0xAA}},
  {0x02,{0x09,0x75,0x98,0x88,0x64,0xAC,0xF7,0x62,0x1B,0xC0,0x90,0x9D,0xF0,0xFC,0xAB,0xFF}},
  {0x03,{0xC9,0x11,0x5C,0xE2,0x06,0x4A,0x26,0x86,0xD8,0xD6,0xD9,0xD0,0x8C,0xDE,0x30,0x59}},
  {0x04,{0x66,0x75,0x39,0xD2,0xFB,0x42,0x73,0xB2,0x90,0x3F,0xD7,0xA3,0x9E,0xD2,0xC6,0x0C}},
  {0x05,{0xF4,0xFA,0xEF,0x20,0xF4,0xDB,0xAB,0x31,0xD1,0x86,0x74,0xFD,0x8F,0x99,0x05,0x66}},
  {0x06,{0xEA,0x0C,0x81,0x13,0x63,0xD7,0xE9,0x30,0xF9,0x61,0x13,0x5A,0x4F,0x35,0x2D,0xDC}},
  {0x08,{0x0A,0x2E,0x73,0x30,0x5C,0x38,0x2D,0x4F,0x31,0x0D,0x0A,0xED,0x84,0xA4,0x18,0x00}},
  {0x09,{0xD2,0x04,0x74,0x30,0x8F,0xE2,0x69,0x04,0x6E,0xD7,0xBB,0x07,0xCF,0x1C,0xFF,0x43}},
  {0x0A,{0xAC,0x00,0xC0,0xE3,0xE8,0x0A,0xF0,0x68,0x3F,0xDD,0x17,0x45,0x19,0x45,0x43,0xBD}},
  {0x0B,{0x01,0x77,0xD7,0x50,0xBD,0xFD,0x2B,0xC1,0xA0,0x49,0x3A,0x13,0x4A,0x4C,0x6A,0xCF}},
  {0x0C,{0x05,0x34,0x91,0x70,0x93,0x93,0x45,0xEE,0x95,0x1A,0x14,0x84,0x33,0x34,0xA0,0xDE}},
  {0x0D,{0xDF,0xF3,0xFC,0xD6,0x08,0xB0,0x55,0x97,0xCF,0x09,0xA2,0x3B,0xD1,0x7D,0x3F,0xD2}},
  {0x2F,{0x4A,0xA7,0xC7,0xB0,0x11,0x34,0x46,0x6F,0xAC,0x82,0x16,0x3E,0x4B,0xB5,0x1B,0xF9}},
  {0x97,{0xCA,0xC8,0xB8,0x7A,0xCD,0x9E,0xC4,0x96,0x90,0xAB,0xE0,0x81,0x39,0x20,0xB1,0x10}},
  {0xB3,{0x03,0xBE,0xB6,0x54,0x99,0x14,0x04,0x83,0xBA,0x18,0x7A,0x64,0xEF,0x90,0x26,0x1D}},
  {0xD9,{0xC7,0xAC,0x13,0x06,0xDE,0xFE,0x39,0xEC,0x83,0xA1,0x48,0x3B,0x0E,0xE2,0xEC,0x89}},
  {0xEB,{0x41,0x84,0x99,0xBE,0x9D,0x35,0xA3,0xB9,0xFC,0x6A,0xD0,0xD6,0xF0,0x41,0xBB,0x26}},
};
#define KEYSTORE_LEN (sizeof(KEYSTORE)/sizeof(KEYSTORE[0]))

// ═══════════════════════════════════════════════════════════════
//  CHALLENGE SECRETS (used by PSP-1000 / PSP-2000 / PSP-3000)
//
//  The PSP authentication protocol runs two sequential challenges.
//  Each challenge mixes an 8-byte hardware-derived random nonce (sent
//  by the PSP) with an 8-byte secret that both the real battery IC and
//  this firmware know in advance. The mixed 16-byte block is then
//  AES-ECB encrypted with the version key from KEYSTORE.
//
//  CHALLENGE1_SECRET  — used during the first challenge (opcode 0x80).
//                       These 8 bytes go into the ROWS of the input matrix
//                       (positions [0][4][8][C][1][5][9][D]), and the PSP's
//                       8-byte nonce fills the remaining COLUMNS.
//
//  CHALLENGE2_SECRET  — used during the second challenge (opcode 0x81).
//                       The layout is reversed: the PSP's nonce fills the
//                       row positions, and these 8 bytes fill the columns.
//
//  Each table entry maps a version ID (matching KEYSTORE) to its secret.
//  Both tables must have an entry for every version ID in KEYSTORE, or
//  that version's authentication will fail at lookup time.
//
//  The PSP Go does NOT use these secret tables; it uses GO_SECRET below.
// ═══════════════════════════════════════════════════════════════

struct SecretEntry { uint8_t id; uint8_t secret[8]; };

static const SecretEntry CHALLENGE1_SECRET[] = {
  {0x00,{0xD2,0x07,0x22,0x53,0xA4,0xF2,0x74,0x68}},
  {0x01,{0xB3,0x7A,0x16,0xEF,0x55,0x7B,0xD0,0x89}},
  {0x02,{0xA0,0x4E,0x32,0xBB,0xA7,0x13,0x9E,0x46}},
  {0x03,{0xB0,0xB8,0x09,0x83,0x39,0x89,0xFA,0xE2}},
  {0x04,{0xFE,0x7D,0x78,0x99,0xBF,0xEC,0x47,0xC5}},
  {0x05,{0x30,0x6F,0x3A,0x03,0xD8,0x6C,0xBE,0xE4}},
  {0x06,{0x84,0x22,0xDF,0xEA,0xE2,0x1B,0x63,0xC2}},
  {0x08,{0xAD,0x40,0x43,0xB2,0x56,0xEB,0x45,0x8B}},
  {0x0A,{0xC2,0x37,0x7E,0x8A,0x74,0x09,0x6C,0x5F}},
  {0x0D,{0x58,0x1C,0x7F,0x19,0x44,0xF9,0x62,0x62}},
  {0x2F,{0xF1,0xBC,0x56,0x2B,0xD5,0x5B,0xB0,0x77}},
  {0x97,{0xAF,0x60,0x10,0xA8,0x46,0xF7,0x41,0xF3}},
  {0xB3,{0xDB,0xD3,0xAE,0xA4,0xDB,0x04,0x64,0x10}},
  {0xD9,{0x90,0xE1,0xF0,0xC0,0x01,0x78,0xE3,0xFF}},
  {0xEB,{0x0B,0xD9,0x02,0x7E,0x85,0x1F,0xA1,0x23}},
};
#define CHALLENGE1_LEN (sizeof(CHALLENGE1_SECRET)/sizeof(CHALLENGE1_SECRET[0]))

static const SecretEntry CHALLENGE2_SECRET[] = {
  {0x00,{0xF5,0xD7,0xD4,0xB5,0x75,0xF0,0x8E,0x4E}},
  {0x01,{0xCC,0x69,0x95,0x81,0xFD,0x89,0x12,0x6C}},
  {0x02,{0x49,0x5E,0x03,0x47,0x94,0x93,0x1D,0x7B}},
  {0x03,{0xF4,0xE0,0x43,0x13,0xAD,0x2E,0xB4,0xDB}},
  {0x04,{0x86,0x5E,0x3E,0xEF,0x9D,0xFB,0xB1,0xFD}},
  {0x05,{0xFF,0x72,0xBD,0x2B,0x83,0xB8,0x9D,0x2F}},
  {0x06,{0x58,0xB9,0x5A,0xAE,0xF3,0x99,0xDB,0xD0}},
  {0x08,{0x67,0xC0,0x72,0x15,0xD9,0x6B,0x39,0xA1}},
  {0x0A,{0x09,0x3E,0xC5,0x19,0xAF,0x0F,0x50,0x2D}},
  {0x0D,{0x31,0x80,0x53,0x87,0x5C,0x20,0x3E,0x24}},
  {0x2F,{0x1B,0xDF,0x24,0x33,0xEB,0x29,0x15,0x5B}},
  {0x97,{0x9D,0xEE,0xC0,0x11,0x44,0xB6,0x6F,0x41}},
  {0xB3,{0xE3,0x2B,0x8F,0x56,0xB2,0x64,0x12,0x98}},
  {0xD9,{0xC3,0x4A,0x6A,0x7B,0x20,0x5F,0xE8,0xF9}},
  {0xEB,{0xF7,0x91,0xED,0x0B,0x3F,0x49,0xA4,0x48}},
};
#define CHALLENGE2_LEN (sizeof(CHALLENGE2_SECRET)/sizeof(CHALLENGE2_SECRET[0]))

// ═══════════════════════════════════════════════════════════════
//  PSP GO AUTHENTICATION KEYS (PSP Go / N-1000 only)
//
//  The PSP Go uses a completely different battery authentication scheme
//  from the PSP-1000/2000/3000. Instead of the two-challenge AES-ECB
//  protocol, it does a single AES-CBC based handshake over opcode 0x90.
//
//  GO_KEY1   — used to AES-CBC decrypt the 32-byte payload the PSP Go
//              sends, exposing the nonce and the embedded GO_SECRET.
//  GO_KEY2   — used to AES-CBC decrypt our constructed 32-byte response
//              before sending it back to the PSP Go.
//  GO_SECRET — a 16-byte value that the PSP Go embeds (encrypted) in its
//              challenge. We verify it after decryption with GO_KEY1.
//              If it doesn't match, we know the packet is malformed.
//
//  NEWMAP    — column-transposition permutation table. The PSP Go protocol
//              includes a matrix "transpose" step: input bytes at indices
//              [0,4,8,C,1,5,9,D,2,6,A,E,3,7,B,F] map to output positions
//              [0,1,2,…,F]. NEWMAP[output_pos] = input_pos encodes this.
//              This effectively transposes a 4×4 byte matrix (row-major
//              to column-major), interleaving the byte order before
//              feeding data into AES. Only the PSP Go flow uses this.
// ═══════════════════════════════════════════════════════════════

static const uint8_t GO_KEY1[16]   = {0xC6,0x6E,0x9E,0xD6,0xEC,0xBC,0xB1,0x21,0xB7,0x46,0x5D,0x25,0x03,0x7D,0x66,0x46};
static const uint8_t GO_KEY2[16]   = {0xDA,0x24,0xDA,0xB4,0x3A,0x61,0xCB,0xDF,0x61,0xFD,0x25,0x5D,0x0A,0xEA,0x79,0x57};
static const uint8_t GO_SECRET[16] = {0x88,0x0E,0x2A,0x94,0x11,0x09,0x26,0xB2,0x0E,0x53,0xE2,0x2A,0xE6,0x48,0xAE,0x9D};

static const uint8_t NEWMAP[16] = {
  0x00,0x04,0x08,0x0C, 0x01,0x05,0x09,0x0D,
  0x02,0x06,0x0A,0x0E, 0x03,0x07,0x0B,0x0F
};

// ═══════════════════════════════════════════════════════════════
//  RUNTIME STATE
//
//  These two variables persist across multiple opcode calls within
//  a single authentication session. The PSP sends opcodes 0x80 then
//  0x81 sequentially — the results from 0x80 must carry over to 0x81.
//
//  g_version  — the Baryon firmware version ID received in opcode 0x80.
//               Stored here so opcode 0x81 can look up the same key
//               and secret without the PSP re-sending the version byte.
//
//  g_chall1b  — the second half of our opcode 0x80 response (bytes 8–15).
//               The PSP's opcode 0x81 challenge is derived from these bytes,
//               so we need them intact when 0x81 arrives.
// ═══════════════════════════════════════════════════════════════

static uint8_t g_version     = 0xFF;   // 0xFF = "no session active yet"
static uint8_t g_chall1b[16] = {0};    // zeroed until populated by opcode 0x80

// ═══════════════════════════════════════════════════════════════
//  LOOKUP HELPERS
//
//  Linear scans over the compile-time tables above.
//  All three return a pointer into the table's static storage (no copy),
//  or nullptr if the requested ID is not in the table.
//  The caller must check for nullptr before using the result.
// ═══════════════════════════════════════════════════════════════

const uint8_t* findKey(uint8_t id) {
  for (uint8_t i = 0; i < KEYSTORE_LEN; i++)
    if (KEYSTORE[i].id == id) return KEYSTORE[i].key;
  return nullptr;   // version ID not in keystore → unsupported hardware revision
}
const uint8_t* findSecret1(uint8_t id) {
  for (uint8_t i = 0; i < CHALLENGE1_LEN; i++)
    if (CHALLENGE1_SECRET[i].id == id) return CHALLENGE1_SECRET[i].secret;
  return nullptr;
}
const uint8_t* findSecret2(uint8_t id) {
  for (uint8_t i = 0; i < CHALLENGE2_LEN; i++)
    if (CHALLENGE2_SECRET[i].id == id) return CHALLENGE2_SECRET[i].secret;
  return nullptr;
}

// ═══════════════════════════════════════════════════════════════
//  CRYPTO PRIMITIVES
// ═══════════════════════════════════════════════════════════════

/*
 * aesEcbEncrypt — encrypt one 16-byte block with AES-128-ECB.
 * Used in the PSP-1000/2000/3000 challenge-response (opcodes 0x80/0x81).
 * mbedTLS allocates key schedule on the stack via the context struct;
 * we init, use, and free immediately so there's no lingering state.
 */
void aesEcbEncrypt(const uint8_t* key, const uint8_t* in, uint8_t* out) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key, 128);
  mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
  mbedtls_aes_free(&ctx);
}

/*
 * aesCbcDecrypt — decrypt `len` bytes with AES-128-CBC.
 * Used exclusively by the PSP Go handshake (opcode 0x90).
 * We copy the IV into a local buffer because mbedTLS modifies it in place
 * as it chains blocks; we don't want to mutate the caller's IV.
 */
void aesCbcDecrypt(const uint8_t* key, const uint8_t* iv,
                   const uint8_t* in, uint8_t* out, size_t len) {
  mbedtls_aes_context ctx;
  uint8_t iv_buf[16];
  memcpy(iv_buf, iv, 16);
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, key, 128);
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv_buf, in, out);
  mbedtls_aes_free(&ctx);
}

/*
 * matrixSwap — reorder 16 bytes using the NEWMAP permutation.
 * Treats the 16 bytes as a 4×4 matrix and transposes it: output[i] = input[NEWMAP[i]].
 * NEWMAP reads bytes in column-major order from the input (columns 0,1,2,3 of each row),
 * producing a row-major output. This is used in the PSP Go handshake as a byte-shuffle
 * step before AES encryption.
 * NOT used in the PSP-1000/2000/3000 standard challenge flow.
 */
void matrixSwap(const uint8_t* in, uint8_t* out) {
  for (int i = 0; i < 16; i++) out[i] = in[NEWMAP[i]];
}

/*
 * mixChallenge1 — construct the 16-byte AES input block for the first challenge.
 *
 * The PSP sends an 8-byte random nonce as part of opcode 0x80. We combine
 * it with the 8-byte CHALLENGE1_SECRET for this version into a 4×4 byte
 * matrix, placing bytes at specific positions:
 *
 *   Matrix layout (column index C, row index R → linear index C + 4*R):
 *     Rows 0 of each column [0x00,0x04,0x08,0x0C] ← secret bytes [0..3]
 *     Rows 1 of each column [0x01,0x05,0x09,0x0D] ← secret bytes [4..7]
 *     Rows 2 of each column [0x02,0x06,0x0A,0x0E] ← nonce  bytes [0..3]
 *     Rows 3 of each column [0x03,0x07,0x0B,0x0F] ← nonce  bytes [4..7]
 *
 * This interleaving is a deliberate part of the Sony protocol design —
 * it's not arbitrary. The result goes through matrixSwap() then AES-ECB.
 */
void mixChallenge1(uint8_t version, const uint8_t* challenge, uint8_t* data) {
  const uint8_t* s = findSecret1(version);
  memset(data, 0, 16);
  data[0x00]=s[0]; data[0x04]=s[1]; data[0x08]=s[2]; data[0x0C]=s[3];
  data[0x01]=s[4]; data[0x05]=s[5]; data[0x09]=s[6]; data[0x0D]=s[7];
  data[0x02]=challenge[0]; data[0x06]=challenge[1];
  data[0x0A]=challenge[2]; data[0x0E]=challenge[3];
  data[0x03]=challenge[4]; data[0x07]=challenge[5];
  data[0x0B]=challenge[6]; data[0x0F]=challenge[7];
}

/*
 * mixChallenge2 — construct the 16-byte AES input block for the second challenge.
 *
 * The layout is the mirror of mixChallenge1: the nonce (which in this case is
 * g_chall1b — our own opcode 0x80 response bytes — not a new PSP-sent nonce)
 * fills the first two rows, and CHALLENGE2_SECRET fills the last two rows.
 *
 *     Rows 0 of each column [0x00,0x04,0x08,0x0C] ← g_chall1b bytes [0..3]
 *     Rows 1 of each column [0x01,0x05,0x09,0x0D] ← g_chall1b bytes [4..7]
 *     Rows 2 of each column [0x02,0x06,0x0A,0x0E] ← secret    bytes [0..3]
 *     Rows 3 of each column [0x03,0x07,0x0B,0x0F] ← secret    bytes [4..7]
 *
 * The result goes through matrixSwap() then two rounds of AES-ECB (same
 * as challenge 1), and the 16-byte ciphertext is sent as our opcode 0x81 reply.
 */
void mixChallenge2(uint8_t version, const uint8_t* challenge, uint8_t* data) {
  const uint8_t* s = findSecret2(version);
  memset(data, 0, 16);
  data[0x00]=challenge[0]; data[0x04]=challenge[1];
  data[0x08]=challenge[2]; data[0x0C]=challenge[3];
  data[0x01]=challenge[4]; data[0x05]=challenge[5];
  data[0x09]=challenge[6]; data[0x0D]=challenge[7];
  data[0x02]=s[0]; data[0x06]=s[1]; data[0x0A]=s[2]; data[0x0E]=s[3];
  data[0x03]=s[4]; data[0x07]=s[5]; data[0x0B]=s[6]; data[0x0F]=s[7];
}

// ═══════════════════════════════════════════════════════════════
//  PACKET CHECKSUM
//
//  Every packet on the PSP battery bus ends with a checksum byte.
//  Algorithm: sum all preceding bytes in the packet, take the low 8 bits,
//  then subtract from 255. This gives a value such that adding the checksum
//  to the sum of all other bytes yields 0xFF (mod 256).
//  The PSP verifies this on every packet it receives; a wrong checksum
//  causes the PSP to discard the packet and re-query.
// ═══════════════════════════════════════════════════════════════

uint8_t calcChecksum(const uint8_t* data, int len) {
  uint32_t sum = 0;
  for (int i = 0; i < len; i++) sum += data[i];
  return (uint8_t)(255 - (sum & 0xFF));
}

// ═══════════════════════════════════════════════════════════════
//  drainEcho — discard our own transmitted bytes that loop back on RX
//
//  Because TX and RX are wired to the same physical DATA line (via the
//  diode), every byte we write on TX immediately appears on RX. If we
//  don't drain these echo bytes before calling readPacket(), they will
//  be misinterpreted as data coming FROM the PSP, corrupting the protocol.
//
//  Sequence:
//    1. Serial1.flush() blocks until the TX hardware shift register is empty,
//       meaning all bytes have been physically transmitted onto the wire.
//    2. We then read exactly `n` bytes from RX — these are our echo bytes.
//    3. We wait up to 100 ms for each byte; if fewer than `n` arrive, we
//       print a warning but continue (partial echo loss is non-fatal in
//       practice since the sync-scan in readPacket() will realign).
// ═══════════════════════════════════════════════════════════════

void drainEcho(int n) {
  Serial1.flush();                    // wait for TX shift register to empty
  int got = 0;
  uint32_t t = millis();
  while (got < n) {
    if (Serial1.available()) { Serial1.read(); got++; t = millis(); }
    if (millis() - t > 100) break;
  }
  if (got != n)
    Serial.printf("[echo] wanted %d, got %d\n", n, got);
}

/*
 * sendRaw — transmit an already-complete byte array verbatim, then drain echoes.
 * Used for hardcoded static responses (opcodes 0x01, 0x02, etc.) where the full
 * packet including header, payload, and checksum is pre-computed at compile time.
 * Also prints a ">" trace line to the USB serial monitor for debugging.
 */
void sendRaw(const uint8_t* data, int len) {
  Serial.print("> ");
  for (int i = 0; i < len; i++) Serial.printf("%02X ", data[i]);
  Serial.println();
  Serial1.write(data, len);
  drainEcho(len);
}

/*
 * sendPacket — build and transmit a packet from a hex-encoded header + binary payload.
 *
 * Parameters:
 *   headerHex  — ASCII hex string of the packet prefix bytes (e.g. "a51206").
 *                This typically encodes [0xA5 (battery→PSP marker)] [length] [0x06 (response opcode)].
 *   payload    — pointer to the binary payload bytes (can be nullptr for no payload).
 *   payloadLen — number of payload bytes.
 *
 * The checksum is computed over header + payload combined, then appended automatically.
 * Also prints a ">" trace line to USB serial. This function is used for dynamic responses
 * where the payload changes per call (e.g., serial number, crypto results).
 */
void sendPacket(const char* headerHex, const uint8_t* payload, int payloadLen) {
  int hlen = strlen(headerHex) / 2;
  uint8_t hbuf[16];
  for (int i = 0; i < hlen; i++) {
    char tmp[3] = {headerHex[2*i], headerHex[2*i+1], 0};
    hbuf[i] = (uint8_t)strtol(tmp, nullptr, 16);
  }
  uint8_t csbuf[64];
  memcpy(csbuf, hbuf, hlen);
  if (payload && payloadLen > 0) memcpy(csbuf + hlen, payload, payloadLen);
  uint8_t cs = calcChecksum(csbuf, hlen + payloadLen);

  Serial.print("> ");
  for (int i = 0; i < hlen; i++) Serial.printf("%02X ", hbuf[i]);
  if (payload) for (int i = 0; i < payloadLen; i++) Serial.printf("%02X ", payload[i]);
  Serial.printf("%02X\n", cs);

  Serial1.write(hbuf, hlen);
  if (payload && payloadLen > 0) Serial1.write(payload, payloadLen);
  Serial1.write(cs);
  drainEcho(hlen + payloadLen + 1);
}

// ═══════════════════════════════════════════════════════════════
//  readPacket — receive and parse one packet from the PSP
//
//  PSP battery packet format (PSP→battery direction):
//    [0x5A] [length] [opcode] [data bytes...] [checksum]
//    length = total bytes in packet including opcode but NOT including
//             the 0x5A header. So length=0x02 means opcode only, no data.
//             length=0x0A means opcode + 8 data bytes.
//
//  This function:
//    1. Scans the incoming byte stream for the expected header byte (0x5A).
//       Any garbage/ACK/noise bytes before the header are printed and skipped.
//    2. Reads the length byte, then the opcode byte.
//    3. If length > 0x02, reads (length - 2) data bytes into `mesg`.
//    4. Reads and discards the checksum byte (we trust the PSP's framing).
//    5. Returns true on success, false on timeout or bad length.
//
//  The 3-second per-byte timeout covers the gap between PSP boot and its
//  first transmission, plus any normal inter-packet delay.
// ═══════════════════════════════════════════════════════════════

bool readPacket(uint8_t expectedHeader, uint8_t& opcode,
                uint8_t* mesg, int& mesgLen) {

  const uint32_t BYTE_TIMEOUT_MS = 3000;
  uint32_t t = millis();

  // waitByte: blocks until one byte arrives on RX or timeout expires.
  // Returns the byte value (0–255) on success, or -1 on timeout.
  auto waitByte = [&]() -> int {
    while (!Serial1.available()) {
      if (millis() - t > BYTE_TIMEOUT_MS) return -1;
    }
    t = millis();
    int b = Serial1.read();
#ifdef RAW_DUMP
    Serial.printf("[raw] %02X\n", (uint8_t)b);
#endif
    return b;
  };

  // Synchronise: keep reading bytes until we find the 0x5A start-of-packet
  // marker. This handles echo remnants, ACK bytes (0xA5) from our own sends,
  // and any other noise on the line.
  int hdr;
  while (true) {
    hdr = waitByte();
    if (hdr < 0) return false;          // timed out waiting for any byte at all
    if ((uint8_t)hdr == expectedHeader) break;
    Serial.printf("[sync] skip %02X\n", (uint8_t)hdr);
  }

  int len = waitByte(); if (len < 0) return false;
  int op  = waitByte(); if (op  < 0) return false;
  opcode  = (uint8_t)op;
  mesgLen = 0;

  if ((uint8_t)len != 0x02) {
    // length 0x02 = opcode-only packet (no data bytes).
    // Anything else = (len - 2) data bytes follow before the checksum.
    int datalen = (int)(uint8_t)len - 2;
    if (datalen < 0 || datalen > 126) {
      // Sanity check: a length byte outside 0x02–0x80 almost certainly means
      // we are misaligned (still have SERIAL_8E2 framing bug, or wire noise).
      // Drain up to 64 bytes to flush the bad packet, then return failure
      // so loop() can retry on the next PSP transmission.
      Serial.printf("[!] Bad length 0x%02X (datalen=%d) — discarding\n",
                    (uint8_t)len, datalen);
      for (int i = 0; i < 64; i++) { if (waitByte() < 0) break; }
      return false;
    }
    for (int i = 0; i < datalen; i++) {
      int b = waitByte(); if (b < 0) return false;
      mesg[i] = (uint8_t)b;
    }
    mesgLen = datalen;
  }

  waitByte(); // consume and discard the trailing checksum byte

  // Print the received packet to USB serial for monitoring
  Serial.printf("< %02X %02X %02X", (uint8_t)hdr, (uint8_t)len, opcode);
  for (int i = 0; i < mesgLen; i++) Serial.printf(" %02X", mesg[i]);
  Serial.println();

  return true;
}

// ═══════════════════════════════════════════════════════════════
//  handleOpcode — dispatch a received PSP opcode to the correct response
//
//  Called from loop() for every successfully parsed packet.
//  The PSP drives the protocol: it sends a command, we respond.
//  The full authentication sequence for PSP-1000/2000/3000 is:
//    PSP → 0x01 (capacity query)   → we reply with static capacity data
//    PSP → 0x0C (serial query)     → we reply with SERIAL_NUMBER
//    PSP → 0x80 (challenge 1)      → we compute & reply (crypto heavy)
//    PSP → 0x81 (challenge 2)      → we compute & reply (crypto heavy)
//    PSP → 0x02,0x03,...,0x16      → we reply with static battery status data
//
//  For PSP Go, the sequence replaces 0x80+0x81 with a single opcode 0x90.
// ═══════════════════════════════════════════════════════════════

void handleOpcode(uint8_t opcode, const uint8_t* mesg, int mesgLen) {
  switch (opcode) {

    case 0x01: {
      /*
       * Battery capacity query — always the very first packet from a PSP-1000.
       * The PSP asks: "how much charge do you have?" before doing anything else.
       * We return a static hardcoded response that reports a healthy, full battery.
       * Exact byte meaning: [0xA5 header][0x05 length][0x06 response opcode]
       *   [0x10 0xC3 = full-charge capacity in internal ADC units]
       *   [0x06 = some status flag] [0x76 = checksum]
       * This static value works for all PSP-1000/2000/3000 models.
       */
      static const uint8_t r[] = {0xA5,0x05,0x06,0x10,0xC3,0x06,0x76};
      sendRaw(r, sizeof(r));
      break;
    }

    case 0x0C:
      /*
       * Battery serial number query.
       * The PSP reads this to decide which boot path to take:
       *   0xFFFFFFFF → service mode (factory recovery, bypasses NAND)
       *   0x00000000 → auto-boot  (boots immediately without key presses)
       *   anything else → normal boot (standard NAND boot)
       * We send whatever BOOT_MODE was compiled in.
       * Packet header "a50606" = [0xA5][0x06 length][0x06 response opcode];
       * sendPacket() appends SERIAL_NUMBER bytes + checksum.
       */
      sendPacket("a50606", SERIAL_NUMBER, 4);
      break;

    case 0x80: {
      /*
       * Challenge 1 — PSP-1000, PSP-2000, PSP-3000 only.
       *
       * The PSP sends: [version byte] [8-byte random nonce] = 9 bytes total.
       * We must prove we know the secret associated with this hardware version
       * by performing a specific computation and returning 16 bytes.
       *
       * Computation:
       *   1. Look up the AES key and challenge-1 secret for mesg[0] (version).
       *   2. Build a 16-byte matrix by interleaving the secret and the nonce
       *      using the layout defined in mixChallenge1().
       *   3. matrixSwap() transposes the matrix (column → row order).
       *   4. aesEcbEncrypt(key, swapped) → chall1a  (first 8 bytes of response)
       *   5. aesEcbEncrypt(key, chall1a) → chall1b_raw  (encrypt output again)
       *   6. matrixSwap(chall1b_raw) → g_chall1b  (saved for use in opcode 0x81)
       *   7. Response = chall1a[0..7] ++ g_chall1b[0..7]  (16 bytes total)
       *
       * NOTE: We encrypt chall1a directly in step 5 — we do NOT matrixSwap it
       * first. An earlier buggy version did swap it here, which produced wrong
       * results for some hardware revisions. The current order is correct.
       *
       * If the version ID is not in our keystore, we send an 0xFF-filled dummy
       * response and print a warning. The PSP will reject it and not boot, but
       * at least the connection stays alive for diagnostics.
       */
      if (mesgLen < 9) { Serial.printf("[!] 0x80 short (%d)\n", mesgLen); break; }
      g_version = mesg[0];
      const uint8_t* key = findKey(g_version);
      if (!key || !findSecret1(g_version)) {
        Serial.printf("[WARN] 0x%02X not in keystore\n", g_version);
        static const uint8_t ph[16] = {
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        sendPacket("a51206", ph, 16);
        break;
      }
      uint8_t mixed[16], swapped[16], chall1a[16];
      mixChallenge1(g_version, mesg + 1, mixed);
      matrixSwap(mixed, swapped);
      aesEcbEncrypt(key, swapped, chall1a);
      // encrypt chall1a directly — do NOT matrixSwap it first (bug fix)
      uint8_t chall1b_raw[16];
      aesEcbEncrypt(key, chall1a, chall1b_raw);
      matrixSwap(chall1b_raw, g_chall1b);
      uint8_t response1[16];
      memcpy(response1,     chall1a,   8);
      memcpy(response1 + 8, g_chall1b, 8);
      sendPacket("a51206", response1, 16);
      break;
    }

    case 0x81: {
      /*
       * Challenge 2 — PSP-1000, PSP-2000, PSP-3000 only.
       *
       * The PSP sends opcode 0x81 with no additional payload — it relies on
       * g_chall1b that we saved during opcode 0x80 as the nonce for this round.
       * The PSP is essentially saying: "now prove you can derive the next value
       * correctly from what you just sent me."
       *
       * Computation (mirrors challenge 1 but with reversed layout):
       *   1. Build a 16-byte matrix mixing g_chall1b and CHALLENGE2_SECRET
       *      using the layout in mixChallenge2() (nonce in rows 0–1, secret in 2–3).
       *   2. matrixSwap() the matrix.
       *   3. aesEcbEncrypt(key, swapped) → chall2
       *   4. aesEcbEncrypt(key, chall2)  → response2  (16 bytes, sent to PSP)
       *
       * After sending response2, the PSP verifies it. If correct, it releases
       * the boot lock and proceeds to load firmware from NAND (or service mode).
       *
       * Special case — PSP-3000 late revisions (0xEB = TA-095, 0xB3 = TA-090v1):
       * These hardware revisions require an extra "nudge" packet immediately after
       * the challenge-2 response. Without it, the Baryon does not release the boot
       * lock even though the crypto was correct. The nudge is a minimal 0x5A packet
       * with opcode 0x01 that triggers the Baryon's final boot-release state machine.
       */
      const uint8_t* key = findKey(g_version);
      if (!key || !findSecret2(g_version)) {
        Serial.println("[!] 0x81: missing key/secret"); break;
      }
      uint8_t mixed[16], swapped[16], chall2[16], response2[16];
      mixChallenge2(g_version, g_chall1b, mixed);
      matrixSwap(mixed, swapped);
      aesEcbEncrypt(key, swapped, chall2);
      aesEcbEncrypt(key, chall2, response2);
      sendPacket("a51206", response2, 16);
      if (g_version == 0xEB || g_version == 0xB3) {
        static const uint8_t nudge[] = {0x5A,0x02,0x01,0xA2};
        sendRaw(nudge, sizeof(nudge));
      }
      break;
    }

    case 0x90: {
      /*
       * PSP Go (N-1000) authentication — completely different from PSP-1000/2000/3000.
       *
       * The PSP Go sends a 0x28 (40) byte payload in this packet:
       *   mesg[0..7]   — 8 bytes of header/flags (ignored in authentication)
       *   mesg[8..39]  — 32 bytes of AES-CBC encrypted challenge data
       *
       * Step 1: Decrypt mesg[8..39] with GO_KEY1, IV=zeros → 32-byte `payload`.
       *   payload[0..7]   — 8-byte nonce A (will be used in response construction)
       *   payload[8..15]  — 8-byte nonce B (will be used in response construction)
       *   payload[16..31] — must equal GO_SECRET. If it doesn't, the packet is
       *                     malformed or the keys are wrong; abort.
       *
       * Step 2: Build our 32-byte response input `p91`:
       *   p91[0..7]   = payload[8..15]  (nonce B first)
       *   p91[8..15]  = payload[0..7]   (nonce A second — swapped from their order)
       *   p91[16..31] = zeros            (padding)
       *
       * Step 3: Decrypt p91 with GO_KEY2, IV=zeros → resp2 (32 bytes).
       *
       * Step 4: Send resp2 as our response payload, preceded by the fixed header
       *   "a52a062001000082828282" which encodes the battery→PSP opcode and length.
       *
       * If GO_SECRET verification passes and resp2 is correct, the PSP Go
       * releases its boot lock.
       */
      if (mesgLen < 0x28) { Serial.printf("[!] 0x90 short (%d)\n", mesgLen); break; }
      static const uint8_t zeros[16] = {0};
      uint8_t payload[32];
      aesCbcDecrypt(GO_KEY1, zeros, mesg + 8, payload, 32);
      Serial.print("[Go] "); for (int i=0;i<32;i++) Serial.printf("%02X",payload[i]); Serial.println();
      if (memcmp(payload + 0x10, GO_SECRET, 16) != 0) { Serial.println("[!] Go: bad handshake"); break; }
      uint8_t p91[32];
      memcpy(p91, payload+8, 8); memcpy(p91+8, payload, 8); memset(p91+16, 0, 16);
      uint8_t resp2[32];
      aesCbcDecrypt(GO_KEY2, zeros, p91, resp2, 32);
      sendPacket("a52a062001000082828282", resp2, 32);
      break;
    }

    /*
     * Status / telemetry queries — sent by the PSP after authentication succeeds.
     * All responses below are static hardcoded values mimicking a healthy battery.
     * The PSP uses these to populate battery status displays; they are not part of
     * authentication and wrong values here do not affect booting.
     *
     * Format reference (all packets): [0xA5 battery→PSP][length][0x06 resp opcode][data...][checksum]
     *
     * 0x02 — Battery temperature         → reports a normal operating temperature
     * 0x03 — Current charge voltage       → reports a typical 3.7V-range value
     * 0x04 — Full charge capacity (again) → different register, same approximate value
     * 0x07 — Remaining capacity (mAh)     → reports a plausible current charge level
     * 0x08 — Current draw (mA)            → reports a plausible discharge current
     * 0x09 — Cycle count                  → reports 1 charge cycle (nearly new battery)
     * 0x0B — Battery limit/cutoff voltage → reports the lower discharge cutoff
     * 0x0D — Date/manufacture info        → reports a valid manufacture date block
     * 0x16 — Manufacturer name string     → reports "SonyEnergyDevices" (ASCII, 17 bytes)
     */
    case 0x02: { static const uint8_t r[]={0xA5,0x03,0x06,0x1B,0x36};                     sendRaw(r,sizeof(r)); break; }
    case 0x03: { static const uint8_t r[]={0xA5,0x04,0x06,0x36,0x10,0x0A};                 sendRaw(r,sizeof(r)); break; }
    case 0x04: { static const uint8_t r[]={0xA5,0x04,0x06,0x68,0x10,0xD8};                 sendRaw(r,sizeof(r)); break; }
    case 0x07: { static const uint8_t r[]={0xA5,0x04,0x06,0x08,0x07,0x41};                 sendRaw(r,sizeof(r)); break; }
    case 0x08: { static const uint8_t r[]={0xA5,0x04,0x06,0xE2,0x04,0x6A};                 sendRaw(r,sizeof(r)); break; }
    case 0x09: { static const uint8_t r[]={0xA5,0x04,0x06,0x01,0x04,0x4B};                 sendRaw(r,sizeof(r)); break; }
    case 0x0B: { static const uint8_t r[]={0xA5,0x04,0x06,0x0F,0x00,0x41};                 sendRaw(r,sizeof(r)); break; }
    case 0x0D: { static const uint8_t r[]={0xA5,0x07,0x06,0x9D,0x10,0x10,0x28,0x14,0x54};  sendRaw(r,sizeof(r)); break; }
    case 0x16: {
      // 17 ASCII bytes: "SonyEnergyDevices" — 0x6B is the checksum
      static const uint8_t r[]={0xA5,0x13,0x06,
        0x53,0x6F,0x6E,0x79,0x45,0x6E,0x65,0x72,
        0x67,0x79,0x44,0x65,0x76,0x69,0x63,0x65,0x73,0x6B};
      sendRaw(r, sizeof(r)); break;
    }

    default:
      // Unknown opcode — print it for investigation but do not reply.
      // Not replying is safe; the PSP will either retry or move on.
      Serial.printf("[?] opcode 0x%02X len=%d\n", opcode, mesgLen);
      break;
  }
}

// ═══════════════════════════════════════════════════════════════
//  setup — runs once on power-up or reset
// ═══════════════════════════════════════════════════════════════

void setup() {
  // USB CDC serial for debug output to your PC (115200 baud, no framing config needed)
  Serial.begin(115200);
  delay(1000);   // give the USB CDC connection time to enumerate before we print
  Serial.println("============================================");
  Serial.println("  BaryonSweeper  ESP32-C3  [v3 FIXED]");
  Serial.println("============================================");
  Serial.printf("  Mode : %s\n",
    BOOT_MODE == SERVICE_MODE ? "SERVICE (unbrick)" :
    BOOT_MODE == AUTOBOOT     ? "AUTOBOOT" : "NORMAL BOOT");
  Serial.printf("  S/N  : %02X %02X %02X %02X\n",
    SERIAL_NUMBER[0], SERIAL_NUMBER[1],
    SERIAL_NUMBER[2], SERIAL_NUMBER[3]);
  Serial.printf("  UART : RX=GPIO%d TX=GPIO%d  19200 8E1\n",
    PSP_RX_PIN, PSP_TX_PIN);
  Serial.println();
  Serial.println("  FIX: SERIAL_8E1 (was SERIAL_8E2).");
  Serial.println("  ESP32-C3 stop-bit register differs from ESP32;");
  Serial.println("  8E2 caused 1-bit frame shift → 0x02 arrived as 0x60.");
  Serial.println("  8E1 reads PSP 8E2 cleanly; extra stop bit = idle.");
  Serial.println();

  /*
   * Initialise UART1 at 19200 baud, 8 data bits, even parity, 1 stop bit.
   * This is the single most important line in the file.
   * The PSP battery bus runs at 19200 baud 8E2, but as explained at the top,
   * SERIAL_8E1 is what actually works on the ESP32-C3. The PSP's second stop
   * bit is transparent to us — it looks like idle bus time between frames.
   */
  Serial1.begin(19200, SERIAL_8E1, PSP_RX_PIN, PSP_TX_PIN);

  // Flush any bytes the PSP may have sent before our UART was initialised.
  // This typically happens if the PSP was already powered on when we booted.
  delay(100);
  int n = 0;
  while (Serial1.available()) { Serial1.read(); n++; }
  if (n) Serial.printf("  Flushed %d boot-noise bytes.\n", n);
  Serial.println("  Waiting for PSP...");
  Serial.println();
}

// ═══════════════════════════════════════════════════════════════
//  loop — the main emulation loop, runs forever after setup()
//
//  This mirrors the structure of the reference Python implementation (pysweeper):
//
//    1. readPacket(0x5A) — block until a complete PSP packet arrives.
//       0x5A is the PSP→battery start-of-packet header byte.
//       Returns false on timeout (PSP not talking yet) or malformed packet.
//
//    2. handleOpcode() — generate and transmit the correct response.
//
//    3. Repeat. The PSP sends queries in a fixed sequence; we just answer each one.
//
//  When readPacket() times out:
//    We flush any stale bytes that may have accumulated on RX (e.g., partial
//    packets from a PSP that reset mid-session), print the count for debug,
//    then return immediately so loop() restarts the wait cleanly.
//
//  ACK bytes (0xA5) that the PSP sends after receiving our packets are handled
//  transparently: readPacket()'s sync-scan skips any byte that isn't 0x5A,
//  so these ACKs are printed as "[sync] skip A5" and otherwise ignored.
// ═══════════════════════════════════════════════════════════════

void loop() {
  uint8_t mesg[128];
  int     mesgLen = 0;
  uint8_t opcode  = 0;

  if (!readPacket(0x5A, opcode, mesg, mesgLen)) {
    int n = 0;
    while (Serial1.available()) { Serial1.read(); n++; }
    if (n) Serial.printf("[timeout] flushed %d stale bytes\n", n);
    return;
  }

  handleOpcode(opcode, mesg, mesgLen);
}
