# OneList CTF - Implementation Documentation

This document details the technical implementation of each flag in the OneList Android CTF challenge. Use this guide when modifying, updating, or maintaining the CTF flags.

## Overview

**Total Flags:** 10  
**Format:** `CYWR{...}`  
**Difficulty:** Progressive (Beginner → Expert)  
**Categories:** Static Analysis (1-5), Dynamic Analysis (6-10)

---

## 🔍 **Static Analysis Flags (1-5)**

### **Flag 1: `CYWR{welcome_to_onelist_ctf}`**
**Type:** Plain text  
**Difficulty:** Beginner (30 seconds)

**Implementation:**
- **File:** `/app/src/main/res/values/strings.xml`
- **Line:** ~50
- **Code:** `<string name="ctf_flag_1">CYWR{welcome_to_onelist_ctf}</string>`

**Discovery Method:**
- Direct string search in main app resources
- Found via `strings`, `grep`, or static analysis tools

**Modification Notes:**
- Keep as plain text for introductory level
- Can change flag content but maintain simplicity
- Ensure it's in main (not debug) resources for easy discovery

---

### **Flag 2: `CYWR{debug_build_config_found}`**
**Type:** Base64 encoded with debug build validation
**Difficulty:** Easy (2 minutes)

**Implementation:**
- **File:** `/core/common/src/debug/res/values/strings.xml`
- **Line:** 5
- **Encoded:** `Q1lXUntkZWJ1Z19idWlsZF9jb25maWdfZm91bmR9`
- **Code:** `<string name="debug_config">Q1lXUntkZWJ1Z19idWlsZF9jb25maWdfZm91bmR9</string>`

**Usage:**
- **File:** `/app/src/main/kotlin/com/lolo/io/onelist/MainActivityViewModel.kt`
- **Lines:** 40-69
- **Code:** `validateDebugEnvironment()` function checks debug build and decodes config

**Discovery Method:**
- Found only in debug build resources
- Actually used in debug environment validation
- Requires Base64 decoding
- Only accessible when running debug build (.debug package suffix)

**Modification Notes:**
- To change flag: `echo -n "NEW_FLAG" | base64`
- Keep in debug resources to teach build variant analysis
- Maintain Base64 encoding for introduction to simple encoding
- Flag is actually processed by debug validation code, making it meaningful

---

### **Flag 3: `CYWR{manifest_scope_analysis}`**
**Type:** Hex encoded in AndroidManifest
**Difficulty:** Easy (5 minutes)

**Implementation:**
- **File:** `/app/src/main/AndroidManifest.xml`
- **Location:** meta-data tag
- **Encoded:** `435957527b6d616e69666573745f73636f70655f616e616c797369737d`

**Code:**
```xml
<meta-data
    android:name="com.onelist.build.config"
    android:value="435957527b6d616e69666573745f73636f70655f616e616c797369737d" />
```

**Discovery Method:**
- Static analysis of AndroidManifest.xml
- Hex decoding of meta-data value
- Look for suspicious or non-standard meta-data entries

**Modification Notes:**
- To change flag: `echo -n "NEW_FLAG" | xxd -p | tr -d '\\n'`
- Keep in manifest to teach Android manifest analysis
- Removed obvious CTF indicators from meta-data name
- Can change meta-data name but keep hex encoding

---

### **Flag 4: `CYWR{caesar_cipher_secrets}`**
**Type:** Caesar cipher (ROT13) with algorithm discovery
**Difficulty:** Easy-Medium (5 minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/utils/TestTags.kt`
- **Encoded:** `PLJE{pnrfne_pvcure_frpergf}`
- **Lines:** 6, 11-36

**Code Structure:**
```kotlin
const val InternalConfig = "PLJE{pnrfne_pvcure_frpergf}"

// Internal config processing - decodes Caesar cipher (ROT13) encoded values
// Caesar cipher with ROT13 - preserves all non-alphabetic characters
fun getDecodedInternalConfig(): String {
    val encoded = InternalConfig
    val decoded = StringBuilder()

    // Apply ROT13 transformation - shifts alphabet by 13 positions
    for (char in encoded) {
        when {
            char in 'A'..'Z' -> {
                // Uppercase letters: A-Z becomes N-Z,A-M
                val shifted = ((char - 'A' + 13) % 26)
                decoded.append(('A' + shifted).toChar())
            }
            char in 'a'..'z' -> {
                // Lowercase letters: a-z becomes n-z,a-m
                val shifted = ((char - 'a' + 13) % 26)
                decoded.append(('a' + shifted).toChar())
            }
            else -> {
                // Preserve all other characters (numbers, symbols, punctuation)
                decoded.append(char)
            }
        }
    }

    return decoded.toString()
}
```

**Usage:**
- **File:** `/feature/lists/src/main/kotlin/com/lolo/io/onelist/feature/lists/ListsScreen.kt`
- **Line:** 96
- **Code:** `val internalFlag = TestTags.getDecodedInternalConfig()`

**Discovery Method:**
1. Find encoded constant in TestTags
2. Analyze `getDecodedInternalConfig()` function
3. Reverse engineer Caesar cipher/ROT13 algorithm
4. Apply decoding (preserves symbols unlike simple ROT13)

**Modification Notes:**
- To change flag: Apply ROT13 to new flag text: `echo "flag" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
- Keep processing function for algorithm discovery learning
- Caesar cipher preserves all non-alphabetic characters (braces, underscores, etc.)
- Can modify the encoding algorithm but update processing function accordingly

---

### **Flag 5: `CYWR{hex_rot47_base64_chain}`**
**Type:** Base64→ROT47→HEX encoding chain
**Difficulty:** Medium-Hard (15 minutes)

**Implementation:**
- **File:** `/core/database/src/main/kotlin/com/lolo/io/onelist/core/database/OneListDatabase.kt`
- **Encoded:** `22603d29263f45402b293937343e685f7d7335372a3e754b2b252a5f29617d402a283d4637226c6c`
- **Lines:** 28, 31-57

**Code Structure:**
```kotlin
const val MIGRATION_SIGNATURE = "22603d29263f45402b293937343e685f7d7335372a3e754b2b252a5f29617d402a283d4637226c6c"

// Migration signature validator - processes Base64→ROT47→HEX encoded signature
fun validateMigrationSignature(): String {
    val encoded = MIGRATION_SIGNATURE

    // Step 1: Convert from hexadecimal to string
    val step1 = try {
        val bytes = encoded.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        String(bytes)
    } catch (e: Exception) { return "invalid" }

    // Step 2: Reverse ROT47 to get Base64 string
    val step2 = StringBuilder()
    for (char in step1) {
        val asciiVal = char.code
        if (asciiVal in 33..126) {
            // Reverse ROT47: subtract 47 and wrap around printable ASCII range
            val reversed = 33 + (asciiVal - 33 - 47 + 94) % 94
            step2.append(reversed.toChar())
        } else {
            step2.append(char)
        }
    }

    // Step 3: Base64 decode to get final flag
    return try {
        String(android.util.Base64.decode(step2.toString(), android.util.Base64.DEFAULT))
    } catch (e: Exception) { "invalid" }
}
```

**Usage:**
- **File:** `/core/database/src/main/kotlin/com/lolo/io/onelist/core/database/di/DaosModule.kt`
- **Line:** 11
- **Code:** `val signature = OneListDatabase.validateMigrationSignature()`

**Discovery Method:**
1. Find encoded constant in database class (valid hex string)
2. Analyze `validateMigrationSignature()` function
3. Reverse engineer 3-step decoding process: HEX → ROT47 → Base64
4. Convert hex to string to get ROT47'd data
5. Apply ROT47 decoding to get Base64 string
6. Decode Base64 to reveal final flag

**Modification Notes:**
- To create new encoding: `hex(rot47(base64(flag)))`
- ROT47 rotates all printable ASCII characters (33-126) by 47 positions
- The stored signature is valid hex but decodes to seemingly random characters
- Keep 3-step process for advanced multi-layer encoding education
- Update both constant and processing function if changing algorithm
- More complex than ROT13 as it affects all symbols and numbers, not just letters
- Base64 encoding ensures the flag is properly encoded before transformation

---

## 🏃 **Dynamic Analysis Flags (6-10)**

### **Flag 6: `CYWR{prefs_storage}`**
**Type:** XOR encrypted, runtime generation  
**Difficulty:** Medium-Hard (30 minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/repository/OneListRepositoryImpl.kt`
- **Lines:** 229-261
- **Trigger:** Create 3 lists, delete 2 lists
- **Storage:** SharedPreferences

**Code Structure:**
```kotlin
private fun validateUserMetrics() {
    // User engagement analytics threshold
    if (preferences.userEngagementCreated >= 3 && preferences.userEngagementDeleted >= 2 && preferences.userToken == null) {
        preferences.userToken = generateUserToken()
    }
}

private fun generateUserToken(): String {
    // Encrypted user engagement token
    val encryptedData = byteArrayOf(
        0x0b, 0x3f, 0x35, 0x30, 0x69, 0x01, 0x11, 0x04, 0x15, 0x04, 0x00, 0x6f,
        0x01, 0x11, 0x0c, 0x15, 0x04, 0x06, 0x04, 0x6f, 0x0c, 0x04, 0x06, 0x15,
        0x04, 0x11, 0x69
    )

    // Multi-byte XOR key derived from app context
    val keyBase = try {
        context.packageName.hashCode()
    } catch (e: Exception) { 42 }

    val xorKey = byteArrayOf(
        (keyBase and 0xFF).toByte(),
        ((keyBase shr 8) and 0xFF).toByte(),
        ((keyBase shr 16) and 0xFF).toByte(),
        0x73.toByte() // Static component
    )

    val decrypted = encryptedData.mapIndexed { index, byte ->
        (byte.toInt() xor xorKey[index % xorKey.size].toInt()).toChar()
    }.joinToString("")

    return decrypted
}
```

**Trigger Logic:**
- **File:** Same file, lines 98-99, 166-167
- **Methods:** `createList()`, `deleteList()` calling `validateUserMetrics()`
- **Counters:** `userEngagementCreated`, `userEngagementDeleted`

**Discovery Method:**
1. Trigger condition through app usage
2. Find flag in SharedPreferences (stored as `user_token`)
3. Analyze `validateUserMetrics()` and `generateUserToken()` methods
4. Reverse engineer XOR decryption

**Modification Notes:**
- Update `encryptedData` array for new flag
- Can change trigger conditions (list counts)
- Keep XOR encryption for dynamic analysis education
- To generate encrypted array: XOR each byte of flag with rotating key

---

### **Flag 7: `CYWR{room_e6_v64hfw4i}`**
**Type:** Hex-encoded with multi-key XOR, database storage  
**Difficulty:** Hard (45 minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/repository/OneListRepositoryImpl.kt`
- **Lines:** 263-288
- **Trigger:** Create list "FLAG", add item "CYWR", mark done
- **Storage:** Room database (special entry with ID 999999)

**Code Structure:**
```kotlin
private suspend fun validateListConfiguration(itemList: ItemList) {
    if (itemList.title.equals("FLAG", ignoreCase = true)) {
        val specialItem = itemList.items.find { 
            it.title.equals("CYWR", ignoreCase = true) && it.done 
        }
        if (specialItem != null) {
            val systemList = ItemList(title = generateSystemMarker(), id = 999999L)
            dao.upsert(systemList.toItemListEntity())
        }
    }
}

private fun generateSystemMarker(): String {
    // Hex-encoded encrypted data
    val encryptedHex = "765915677b305a6f2f6a65746a767401682442342b48"
    
    // Convert hex string to bytes
    val encryptedBytes = encryptedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    
    // Context-derived seed for key generation (normalize package name across builds)
    val basePackage = context.packageName.replace(".debug", "").replace(".tst", "")
    val seed = context.applicationInfo.targetSdkVersion + basePackage.length
    
    // Generate 3 different XOR keys from seed
    val key1 = (seed and 0xFF).toByte()
    val key2 = ((seed shr 8) and 0xFF).toByte()
    val key3 = 0x42.toByte() // Static component
    
    // Apply rotating XOR decryption
    val decrypted = encryptedBytes.mapIndexed { index, byte ->
        val keyToUse = when (index % 3) {
            0 -> key1
            1 -> key2
            else -> key3
        }
        (byte.toInt() xor keyToUse.toInt()).toChar()
    }.joinToString("")
}
```

**Encryption Method:**
1. **Step 1:** Flag is XOR encrypted with rotating 3-key pattern
2. **Step 2:** Encrypted bytes are encoded as hex string
3. **Step 3:** Keys are derived from app context (SDK version + package name length)

**Trigger Logic:**
- **File:** Same file, line 116
- **Method:** `saveList()` calling `validateListConfiguration()`
- **Trigger condition:** List title equals "FLAG" AND contains item "CYWR" marked as done

**Discovery Method:**
1. Trigger condition through specific list/item creation
2. Find special database entry with ID 999999
3. Analyze `validateListConfiguration()` and `generateSystemMarker()` methods
4. Reverse engineer hex decoding + multi-key XOR decryption

**Modification Notes:**
- Update `encryptedHex` for new flag (XOR with 3-key rotation, then hex encode)
- Can change trigger list/item names ("FLAG", "CYWR")
- Key derivation uses context.applicationInfo.targetSdkVersion + basePackage.length (normalized)
- Base package normalization: removes ".debug" and ".tst" suffixes for consistency
- Static key component is 0x42 (can be changed)
- Current values: targetSdk=34, basePackage="com.lolo.io.onelist" (19 chars), seed=53
- To generate new encrypted hex: XOR flag with rotating keys (seed=53), then convert bytes to hex

---

### **Flag 8: `CYWR{asset_steganography_master}`**
**Type:** Asset steganography with AES encryption  
**Difficulty:** Very Hard (60+ minutes)

**Implementation:**
- **File:** `/feature/settings/src/main/kotlin/com/lolo/io/onelist/feature/settings/fragment/SettingsFragmentViewModel.kt`
- **Lines:** 69-122
- **Trigger:** Tap version number 10 times
- **Method:** AES CBC/NoPadding encryption with key+IV extraction from image asset
- **Asset:** `/app/src/main/assets/icon.jpg` (with appended key;IV data)
- **Crypto:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/crypto/CryptoUtils.kt`

**Code Structure:**
```kotlin
fun processSystemData() {
    viewModelScope.launch {
        try {
            val result = extractDataFromAsset()
            Log.d("OneList_System", "Process completed: $result")
        } catch (e: Exception) {
            Log.e("OneList_System", "Process failed", e)
        }
    }
}

private suspend fun extractDataFromAsset(): String = withContext(Dispatchers.IO) {
    val encryptedData = "vZnAenSqeZZk0z69SDsvOBSggL6DAVnXV3LGGtqGlzk="
    val (secretKey, initVector) = extractKeyAndIvFromResource()
    val processedData = CryptoUtils.decryptWithKeyAndIv(encryptedData, secretKey, initVector)
    return@withContext processedData
}

private fun extractKeyAndIvFromResource(): Pair<String, String> {
    val inputStream = context.assets.open("icon.jpg")
    val allBytes = inputStream.readBytes()
    
    // Key and IV are at the end, separated by semicolon
    // Format: "base64_key;base64_iv"
    val tailData = String(allBytes.takeLast(49).toByteArray()) // 24+1+24 = 49 chars
    val parts = tailData.split(";")
    
    if (parts.size == 2) {
        val encodedKey = parts[0]
        val encodedIv = parts[1]
        
        val decodedKey = Base64.decode(encodedKey, Base64.DEFAULT)
        val decodedIv = Base64.decode(encodedIv, Base64.DEFAULT)
        
        val secretKey = String(decodedKey)
        val initVector = String(decodedIv)
        
        return Pair(secretKey, initVector)
    } else {
        return Pair("fallback_key", "fallback_iv")
    }
}
```

**Encryption Details:**
- **Key:** `Thi$_1s_d4-WaaaY` (base64: `VGhpJF8xc19kNC1XYWFhWQ==`)
- **IV:** `YaaaW-4d_s1_$ihT` (base64: `WWFhYVctNGRfczFfJGloVA==`)
- **Algorithm:** AES CBC/NoPadding (16-byte key/IV, no padding)
- **Encrypted Flag:** `vZnAenSqeZZk0z69SDsvOBSggL6DAVnXV3LGGtqGlzk=`
- **Asset Data:** `VGhpJF8xc19kNC1XYWFhWQ==;WWFhYVctNGRfczFfJGloVA==` (appended to icon.jpg)

**Discovery Method:**
1. Trigger through UI interaction (tap version number 10 times in settings)
2. Monitor logcat for "OneList_System" outputs
3. Reverse engineer `extractDataFromAsset()` method
4. Analyze `extractKeyAndIvFromResource()` function
5. Extract and analyze icon.jpg asset file
6. Discover key;IV data at end of image (last 49 bytes)
7. Decode base64 to get AES key and IV
8. Implement AES CBC/NoPadding decryption
9. Decrypt encrypted flag to get final result

**Modification Notes:**
- To change encryption: Update key, IV, and re-encrypt flag using AES CBC/NoPadding
- Asset format: Append `base64_key;base64_iv` to end of icon.jpg
- Can change trigger count in SettingsFragment.kt
- Update CryptoUtils.decryptWithKeyAndIv() for different crypto algorithms
- Current key/IV lengths: 16 bytes each (perfect for AES-128)
- Teaches: Asset manipulation, steganography, AES encryption, binary analysis

---

### **Flag 9: `CYWR{dynamic_code_loading_malware_wannabe}`**
**Type:** Dynamic Code Loading (DCL) with external DEX, NotificationService simulation
**Difficulty:** Expert (90+ minutes)

**Implementation:**
- **Main File:** `/feature/lists/src/main/kotlin/com/lolo/io/onelist/feature/lists/ListScreenViewModel.kt`
- **Lines:** 249-357
- **External DEX:** `/rwyc/onelist/external/classes.dex` (hosted on GitHub, 2424 bytes)
- **DEX Build Script:** `/rwyc/onelist/build-dex.sh` (builds DEX from Java source)
- **Manifest Entry:** AndroidManifest.xml declares service with `tools:ignore="MissingClass"`
- **Trigger:** Long-press app title 7 times (method: `onTitleLongPress()`)
- **Method:** Downloads DEX, loads with DexClassLoader, starts service with Intent

**Architecture:**
```
Main App (AndroidManifest.xml declares NotificationListener service)
    ↓ (Service class not found in static analysis)
    ↓ (Indicates Dynamic Code Loading)
    ↓
Heavy Obfuscation Layer
    ↓ (Base64 encoded URLs, class names, method names)
    ↓ (Reflection for network checks, class loading)
    ↓
External DEX Download (GitHub)
    ↓ (https://raw.githubusercontent.com/cywr/rwyc/main/onelist/external/classes.dex)
    ↓
DexClassLoader + Reflection
    ↓ (Load com.onelist.external.NotificationService)
    ↓ (Access getData() method)
    ↓
Flag Retrieved via Reflection (Hex decoded at runtime)
```

**External DEX Structure:**
- **Source:** `/rwyc/onelist/src/com/onelist/external/NotificationService.java`
- **Package:** `com.onelist.external.NotificationService`
- **Purpose:** Simulates malware NotificationService behavior
- **Flag Method:** `getData()` - Hex-encoded flag decoded at runtime
- **Hex Data:** `435957527b64796e616d69635f636f64655f6c6f6164696e675f6d616c776172655f77616e6e6162657d`
- **Decoding:** Built-in hex-to-string conversion in `getData()` method
- **Lifecycle Logging:** Constructor, onCreate(), onDestroy(), onNotificationPosted/Removed() with Tag "NotificationService"
- **Service Methods:** Proper NotificationListenerService lifecycle implementation

**DEX Build Process:**
```bash
# Build script: /rwyc/onelist/build-dex.sh
# 1. Creates _build directory (not temp)
# 2. Compiles Java with Android SDK classpath
# 3. Creates JAR from compiled classes
# 4. Converts JAR to DEX using Android d8 tool
# 5. Outputs to external/classes.dex (2424 bytes with logging)
```

**Stealth Obfuscation Techniques:**
```kotlin
// Advanced string obfuscation using AppEnvironment
// Uses polyalphabetic substitution cipher (Vigenère-style) + string interleaving

// AppEnvironment.kt - Encrypted configuration properties
internal object AppEnvironment {
    // Encrypted configuration properties using advanced cipher techniques
    private const val CONFIG_A = "dxnxoxmxwxsx.xtxqxqxlxxxqx.xDxrxaxTxzxixvxtxDxmxsxwxixd"
    private const val CONFIG_B = "jxhxfxexgx:x/x/xkxbxhx.xgxlxvxvxgxqxixfxixexvxpxyxhxexqxvx..."
    private const val CONFIG_C = "uxsxdx.xwxpxixmxuxyxfx.xwxbxkxzxzxpxexmx.xTxaxmxaxjxzxxxixvxmxpxzxYxqxkxnxmxtxz"
    private const val CONFIG_D = "lxbxdxuxQxtxdxtxk"
    private const val CONFIG_E = "ixsxfxSxoxgxe"
    private const val CONFIG_F = "gxrxTxmxmxcxxxf"
    private const val CONFIG_G = "nxrxz"

    // Security context parameters for decryption routines
    private val securityContext1 = "android.system"
    private val securityContext2 = "component.load"
    private val securityContext3 = "service.mgmt"

    // Multi-key decryption with Vigenère cipher
    private fun decrypt(encryptedData: String, securityContext: String): String {
        val result = StringBuilder()
        val key = securityContext.lowercase()

        for (i in encryptedData.indices) {
            val encChar = encryptedData[i]
            val keyChar = key[i % key.length]

            when {
                encChar.isLowerCase() -> {
                    val shift = keyChar - 'a'
                    val decrypted = ((encChar - 'a' - shift + 26) % 26) + 'a'.code
                    result.append(decrypted.toChar())
                }
                // ... handles uppercase and symbols
            }
        }
        return result.toString()
    }

    // String deinterleaving - extracts from interleaved pattern
    private fun deinterleave(interleavedData: String): String {
        val result = StringBuilder()
        for (i in interleavedData.indices step 2) {
            result.append(interleavedData[i])
        }
        return result.toString()
    }

    // Generic property access without revealing purpose
    fun getProperty(configId: Char): String = when (configId) {
        'A' -> resolveSecureProperty(CONFIG_A, securityContext1)
        'B' -> resolveSecureProperty(CONFIG_B, securityContext2)
        'C' -> resolveSecureProperty(CONFIG_C, securityContext3)
        // ... more configs
        else -> ""
    }

    fun resolveRuntimeProperty(propertyIndex: Int): String {
        return when (propertyIndex) {
            0 -> getProperty('D')  // Method names accessed by index
            1 -> getProperty('E')
            2 -> getProperty('F')
            else -> ""
        }
    }
}

// Usage in ListScreenViewModel - no obvious purpose revealed
val loaderClassString = AppEnvironment.getProperty('A')
val serviceClassName = AppEnvironment.getProperty('C')
val downloadUrl = AppEnvironment.getProperty('B')
val methodName = AppEnvironment.resolveRuntimeProperty(0)
```

**Discovery Method:**
1. **Static Analysis Clues:**
   - AndroidManifest.xml declares `com.onelist.external.NotificationService` with BIND_NOTIFICATION_LISTENER_SERVICE permission
   - Service class not found in static analysis (jadx, apktool) - marked with `tools:ignore="MissingClass"`
   - Indicates Dynamic Code Loading pattern

2. **Dynamic Analysis Required:**
   - Trigger via long-press app title 7 times (method: `onTitleLongPress()`)
   - Monitor network traffic for DEX download (stealth download to cache/updates/)
   - Monitor file system for temporary DEX files (component_*.dat, then deleted)
   - Monitor logcat for "NotificationService" tag to verify DEX loading
   - Silent failures for stealth (no obvious debug output)

3. **Advanced Analysis:**
   - Discover AppEnvironment class with generic encrypted properties
   - Reverse engineer polyalphabetic substitution cipher (Vigenère-style)
   - Understand string deinterleaving pattern (every 2nd character)
   - Map CONFIG_A/B/C/D/E/F/G to actual purposes through usage analysis
   - Identify security contexts: "android.system", "component.load", "service.mgmt"
   - Correlate getProperty('B') usage to determine it's a URL
   - Correlate getProperty('A') and getProperty('C') to class/service names
   - Correlate resolveRuntimeProperty(0/1/2) to method names
   - Analyze stealth methods: `performSystemUpdate()`, `downloadSystemComponent()`, `initializeSystemService()`
   - Understand realistic Service binding simulation
   - Extract and analyze downloaded DEX file
   - Find flag in NotificationService class via hex decoding

4. **Flag Extraction:**
   - Analyze AppEnvironment.getProperty('B') usage to identify download URL
   - Reverse engineer string decryption: deinterleave then decrypt with Vigenère cipher
   - Extract URL: `https://raw.githubusercontent.com/cywr/rwyc/main/onelist/external/classes.dex`
   - Extract service class from AppEnvironment.getProperty('C'): `com.onelist.external.NotificationService`
   - Download and analyze DEX: `jadx classes.dex`
   - Find `com.onelist.external.NotificationService.getData()` method
   - Discover hex-encoded flag data: `435957527b64796e616d69635f636f64655f6c6f6164696e675f6d616c776172655f77616e6e6162657d`
   - Decode hex to ASCII or understand the hex-to-string conversion logic
   - Extract flag: `CYWR{dynamic_code_loading_malware_wannabe}`

**Security Educational Value:**
- **DCL Detection:** Teaches how to identify dynamic code loading in Android malware
- **Manifest Analysis:** Shows importance of correlating manifest with actual code
- **Network Monitoring:** Demonstrates stealth DEX download behavior
- **Polyalphabetic Cipher Analysis:** Advanced cryptographic obfuscation beyond simple XOR
- **Service Binding Simulation:** Realistic NotificationListener malware pattern
- **Stealth Operations:** Silent failures, no debug logging, file cleanup
- **Advanced Obfuscation:** Multiple layers of hiding (XOR, reflection, stealth naming)

**Modification Notes:**
- Update GitHub URL in AppEnvironment.CONFIG_B (polyalphabetic cipher + interleaving)
- Change cipher security contexts: "android.system", "component.load", "service.mgmt" for different obfuscation
- Modify service class name in AppEnvironment.CONFIG_C
- Re-encrypt all CONFIG_A through CONFIG_G with new key phrases if changed
- Update stealth method names: `onTitleLongPress()`, `performSystemUpdate()`, `downloadSystemComponent()`, `initializeSystemService()`
- Change trigger mechanism or count (currently 7 long-presses)
- Update external DEX with new flag content using build script
- DEX build script at `/rwyc/onelist/build-dex.sh` for rebuilding external DEX
- Hex-encoded flag requires hex-to-string conversion logic in DEX
- Current hex: `435957527b64796e616d69635f636f64655f6c6f6164696e675f6d616c776172655f77616e6e6162657d`
- Lifecycle logging uses "NotificationService" tag for verification
- Silent failure behavior mimics real malware patterns
- AndroidManifest service declaration with `tools:ignore="MissingClass"` for lint warnings

---

### **Flag 10: `CYWR{native_reverse_engineering}`**
**Type:** Native C++ with image steganography and multi-key XOR
**Difficulty:** Medium-Hard (45-60 minutes)

**Implementation:**
- **Native Module:** `/core/native/` with NDK/CMake build system
- **JNI Interface:** `/core/native/src/main/kotlin/com/lolo/io/onelist/core/native/NativeCrypto.kt`
- **C++ Engine:** `/core/native/src/main/cpp/native_crypto.cpp` and `/core/native/src/main/cpp/flag_engine.cpp`
- **Trigger:** Automatic after Flag 6 completion (10 second delay)
- **Method:** LSB steganography + native XOR decryption
- **Assets:** `background.png` and `icon_large.png` with embedded 8-byte keys

**Key Architecture:**
- **Key Component 1:** Hidden in `app/src/main/assets/background.png` via LSB steganography
- **Key Component 2:** Hidden in `app/src/main/assets/icon_large.png` via LSB steganography
- **Key Component 3:** Hardcoded in native binary (`native_key[]` array)
- **Combination:** XOR all three 8-byte components to create final decryption key
- **Encryption:** XOR encrypted flag using combined key

**Code Structure:**
```cpp
// Encrypted flag data (32 bytes)
const unsigned char encrypted_flag[] = {
    0x6f, 0x0e, 0xe2, 0x5d, 0x06, 0xe9, 0x69, 0x48, 0x45, 0x21, 0xd0, 0x50,
    0x0f, 0xe2, 0x7e, 0x59, 0x5e, 0x24, 0xd0, 0x50, 0x18, 0xe9, 0x6f, 0x55,
    0x42, 0x32, 0xd0, 0x7d, 0x14, 0xe9, 0x6f, 0x41
};

// Native key component (8 bytes)
const unsigned char native_key[] = {
    0x4e, 0x41, 0x54, 0x49, 0x56, 0x45, 0x43, 0x52  // "NATIVECR"
};

// Key combination and XOR decryption logic
void combine_keys(unsigned char* combined_key) {
    for (int i = 0; i < 8; i++) {
        combined_key[i] = image_keys[0][i] ^ image_keys[1][i] ^ native_key[i];
    }
}
```

**Integration Points:**
- **App.kt:** Native library loading and initialization after Flag 6 completion
- **Build System:** NDK configuration in `core/native/build.gradle.kts` and `CMakeLists.txt`
- **Assets:** Steganography images with 8-byte keys embedded via LSB method

**Discovery Method:**
1. **Static Analysis Phase:**
   - Find native library `libonelist_native.so` in APK `lib/` folder
   - Discover `NativeCrypto` class and JNI method signatures in decompiled code
   - Identify asset files `background.png` and `icon_large.png`
   - Analyze App.kt for native library loading logic

2. **Dynamic Analysis Phase:**
   - Trigger Flag 6 completion to enable native processing
   - Monitor logcat for "OneListApp", "NativeCrypto", and "FlagEngine" tags
   - Observe 10-second delay, then 5-second additional delay before flag processing
   - Native processing logs the decrypted flag directly to logcat

3. **Native Reverse Engineering Phase:**
   - Use Ghidra/IDA Pro/Radare2 to analyze `libonelist_native.so`
   - Extract key components from images using steganography tools (LSB extraction)
   - Discover encrypted flag data and native key component in binary
   - Reverse engineer XOR combination and decryption algorithm

4. **Flag Extraction Methods:**
   - **Method A:** Monitor logcat after triggering native processing: `adb logcat | grep FlagEngine`
   - **Method B:** Extract keys manually and replicate decryption in standalone tool
   - **Method C:** Hook native functions with Frida to intercept flag during processing
   - **Method D:** Static analysis of native binary to extract all components

**Image Steganography Details:**
- **Format:** PNG (lossless compression, preserves LSB data)
- **Method:** Least Significant Bit (LSB) of red channel only
- **Structure:** 8-bit length prefix + data bits
- **Key Size:** 8 bytes (64 bits) per image
- **Python Test Script:** `/rwyc/onelist/test_flag10_crypto.py` validates entire process

**Current Key Values (from test run):**
- **Background key:** `30a2a36656cba923`
- **Icon_large key:** `52b442207d09e24d`
- **Native key:** `4e41544956454352`
- **Combined key:** `2c57b50f7d87083c`
- **Encrypted flag:** `6f0ee25d06e969484521d0500fe27e595e24d05018e96f554232d07d14e96f41`

**Educational Value:**
- **Native Reverse Engineering:** Introduction to Android NDK/JNI analysis
- **Image Steganography:** LSB extraction techniques and tools
- **Multi-layer Cryptography:** Key combination via XOR operations
- **Build System Understanding:** NDK/CMake configuration analysis
- **Cross-language Analysis:** Java/Kotlin ↔ C++ debugging techniques

**Tools Required:**
- **Static Analysis:** Ghidra, IDA Pro, Radare2, objdump, readelf
- **Steganography:** StegSolve, binwalk, custom LSB extraction tools
- **Dynamic Analysis:** adb logcat, optional Frida for advanced hooking
- **Image Processing:** Tools capable of LSB analysis (Python PIL, GIMP with plugins)

**Modification Notes:**
- **Regenerate Keys:** Run `test_flag10_crypto.py` to create new key components and images
- **Update Native Code:** Modify `encrypted_flag[]` and `native_key[]` arrays in `flag_engine.cpp`
- **Change Timing:** Adjust delays in App.kt (currently 10s + 5s)
- **Modify Images:** Replace source images in `/rwyc/onelist/assets/` and regenerate
- **Key Size:** Can change from 8 bytes, but update all components consistently
- **Algorithm:** Can replace XOR with other operations, but maintain educational complexity

---

## 🔧 **Common Modification Patterns**

### **Encoding Changes:**
- **Base64:** `echo -n "flag" | base64`
- **ROT13:** `echo "flag" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
- **ROT47:** Custom implementation needed (rotates all printable ASCII 33-126)
- **Hex:** `echo -n "flag" | xxd -p | tr -d '\n'`
- **XOR:** Custom implementation needed

### **Adding New Flags:**
1. Choose location (file and line)
2. Implement encoding/encryption
3. Add processing function (for discovery)
4. Add usage/trigger code
5. Update documentation
6. Test discovery method

### **Changing Triggers:**
- Update condition logic in trigger functions
- Modify counters or interaction requirements
- Ensure triggers are discoverable through analysis
- Update solution documentation

### **Testing Changes:**
1. **Debug Build** (for testing): `./gradlew assembleDebug`
2. **Release Build** (for CTF): `./gradlew assembleRelease`
3. Test static flags through decompilation
4. Test dynamic flags through app interaction
5. Verify encoding/decoding works correctly
6. Update solution guide

### **Enhanced Build Configuration:**

#### **Obfuscation Features:**
- **R8/ProGuard**: Aggressive code minification and obfuscation
- **Class Name Obfuscation**: All classes renamed to generic names (a.b.c...)
- **Method Name Obfuscation**: All methods renamed to short names (a, b, c...)
- **String Obfuscation**: Constant strings are obfuscated where possible
- **Control Flow Obfuscation**: Code structure made harder to analyze
- **Resource Shrinking**: Unused resources and debugging info removed
- **Debug Symbol Removal**: Stack traces and variable names obfuscated

#### **Build Commands:**
```bash
# Debug build - aggressive obfuscation enabled (non-debuggable)
./gradlew assembleDebug

# Release build - aggressive obfuscation enabled
./gradlew assembleRelease

# Clean build (recommended before building)
./gradlew clean assembleDebug
./gradlew clean assembleRelease
```

#### **Obfuscation Configuration Files:**
- `app/proguard-rules.pro` - Basic ProGuard rules + library compatibility
- `app/proguard-ctf.pro` - Specialized CTF obfuscation with maximum aggression
- `app/build.gradle.kts` - Build configuration with enhanced minification for both debug and release

#### **Enhanced Obfuscation Features:**
- **7 Optimization Passes**: Maximum R8 optimization cycles
- **Complete Package Flattening**: All packages renamed to single letters (a, b, c...)
- **Aggressive Interface Merging**: `-mergeinterfacesaggressively`
- **Method Overloading**: `-overloadaggressively` for maximum name confusion
- **String Encryption**: Advanced polyalphabetic substitution + interleaving for Flag 9
- **Parameter Name Removal**: All reflection debugging info stripped
- **BuildConfig Obfuscation**: Debug fields removed, only VERSION_NAME preserved

#### **What Gets Obfuscated:**
- **Flag 9 AppEnvironment**: Fully obfuscated with encrypted string storage
- **Reflection Strings**: DexClassLoader, NotificationService, method names (encrypted)
- **SharedPreferences Keys**: user_token, user_engagement_* keys (stealth naming)
- **Package Structure**: Completely flattened to random single-letter packages
- **Line Numbers**: Removed to make stack trace analysis impossible
- **Parameter Names**: All removed to make reflection analysis harder
- **Class Names**: All renamed to meaningless single letters
- **Method Names**: All renamed to a(), b(), c(), etc.

#### **What's Preserved (Minimal):**
- **Essential Android Framework**: Only Activity and Service base classes
- **GSON Serialization**: Data classes for JSON persistence (minimal keeps)
- **Jackson Libraries**: External library compatibility
- **Essential BuildConfig**: Only VERSION_NAME field for app functionality

#### **Analysis Impact:**
- **Static Analysis**: All class/method names become meaningless single letters (a.b.c.d())
- **Dynamic Analysis**: Stack traces completely obfuscated, no meaningful names
- **String Analysis**: Flag 9 strings encrypted with custom cipher, no plaintext
- **Package Analysis**: Completely flat structure, no logical organization visible
- **Decompilation**: Jadx/apktool output extremely difficult to understand
- **Reflection Analysis**: No parameter names, minimal debugging information
- **Variable Names**: All local variables renamed to single letters

#### **Debug vs Release Builds:**
- **Both builds**: Apply identical aggressive obfuscation settings
- **Debug build**: `isDebuggable = false` to enable full R8 obfuscation
- **Application ID**: Debug uses `.debug` suffix, release uses production ID
- **Crashlytics**: Disabled for debug builds, enabled for release
- **Signing**: Debug uses debug keystore, release uses production signing (disabled for testing)

---

## 📋 **File Structure Summary**

```
Static Flags:
├── app/src/main/res/values/strings.xml (Flag 1)
├── core/common/src/debug/res/values/strings.xml (Flag 2)
├── app/src/main/AndroidManifest.xml (Flag 3)
├── core/data/src/main/kotlin/.../TestTags.kt (Flag 4)
└── core/database/src/main/kotlin/.../OneListDatabase.kt (Flag 5)

Dynamic Flags:
├── core/data/src/main/kotlin/.../OneListRepositoryImpl.kt (Flags 6, 7)
├── feature/settings/src/main/kotlin/.../SettingsScreen.kt (Flag 8)
├── feature/lists/src/main/kotlin/.../ListScreenViewModel.kt (Flag 9)
└── core/data/src/main/kotlin/.../CryptoUtils.kt (Flag 10)

Usage/Triggers:
├── app/src/main/kotlin/.../MainActivityViewModel.kt (Flag 2 debug validation)
├── feature/lists/src/main/kotlin/.../ListsScreen.kt (Flag 4 usage)
├── core/database/src/main/kotlin/.../DaosModule.kt (Flag 5 usage)
└── Various repository methods (Dynamic flag triggers)
```

---

## ⚠️ **Important Notes**

1. **Always test after modifications** - Build and verify flags work
2. **Maintain difficulty progression** - Keep learning curve intact
3. **Update documentation** - Modify README.md and solution.md when changing flags
4. **Preserve discovery methods** - Ensure processing functions remain for algorithm discovery
5. **Test both static and dynamic** - Verify through jadx and runtime analysis
6. **Keep backups** - Save working versions before major changes

This implementation guide should be updated whenever flags are modified to maintain accuracy and ease future development.