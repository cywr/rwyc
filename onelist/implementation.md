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
- **Lines:** 230-261
- **Trigger:** Create 3 lists, delete 2 lists
- **Storage:** SharedPreferences

**Code Structure:**
```kotlin
private fun validateUserMetrics() {
    if (preferences.ctfListsCreated >= 3 && preferences.ctfListsDeleted >= 2) {
        preferences.ctfFlag6 = generateUserToken()
    }
}

private fun generateUserToken(): String {
    val encryptedData = byteArrayOf(0x0b, 0x3f, 0x35, ...) // XOR encrypted
    val keyBase = context.packageName.hashCode()
    val xorKey = byteArrayOf(
        (keyBase and 0xFF).toByte(),
        ((keyBase shr 8) and 0xFF).toByte(),
        ((keyBase shr 16) and 0xFF).toByte(),
        0x73.toByte()
    )
    // Multi-byte XOR decryption
}
```

**Trigger Logic:**
- **File:** Same file, lines 91-101, 151-167
- **Methods:** `createList()`, `deleteList()` calling `validateUserMetrics()`
- **Counters:** `ctfListsCreated`, `ctfListsDeleted`

**Discovery Method:**
1. Trigger condition through app usage
2. Find flag in SharedPreferences
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
- **Lines:** 232-406
- **External DEX:** `/rwyc/onelist/external/classes.dex` (hosted on GitHub)
- **Trigger:** Long-press app title 7 times
- **Method:** Downloads DEX, loads with DexClassLoader, uses reflection to access hidden method

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
    ↓ (https://raw.githubusercontent.com/cynychwr/ctfs/main/rwyc/onelist/external/classes.dex)
    ↓
DexClassLoader + Reflection
    ↓ (Load com.onelist.external.NotificationService)
    ↓ (Access getFlag() method)
    ↓
Flag Retrieved via Reflection
```

**External DEX Structure:**
- **File:** `com.onelist.external.NotificationService`
- **Purpose:** Simulates malware NotificationService behavior
- **Flag Method:** `getFlag()` - Contains flag accessible via reflection
- **Decoy Methods:** `getServiceStatus()`, `onNotificationPosted()`, `onNotificationRemoved()`

**Obfuscation Techniques:**
```kotlin
// Base64 encoded sensitive strings
private val systemConfig = listOf(
    "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2N5bnljaHdyL2N0ZnMv", // URL part 1
    "bWFpbi9yd3ljL29uZWxpc3QvZXh0ZXJuYWwvY2xhc3Nlcy5kZXg=", // URL part 2 (classes.dex)
    "Y29tLm9uZWxpc3QuZXh0ZXJuYWwuTm90aWZpY2F0aW9uU2VydmljZQ==", // Service class
    "Z2V0RmxhZw==", // Flag method (getFlag)
    "T25lTGlzdF9NYWx3YXJl" // Log tag
)

// Heavy reflection for class loading
val dexClassLoaderClass = Class.forName(
    StringBuilder("dalvik.system.").append("DexClassLoader").toString()
)

// Network connectivity check via reflection
val connectivityClass = Class.forName(
    StringBuilder("android.net.").append("ConnectivityManager").toString()
)
```

**Discovery Method:**
1. **Static Analysis Clues:**
   - AndroidManifest.xml declares `NotificationService` with BIND_NOTIFICATION_LISTENER_SERVICE permission
   - Service class not found in static analysis (jadx, apktool)
   - Indicates Dynamic Code Loading

2. **Dynamic Analysis Required:**
   - Trigger via long-press app title 7 times
   - Monitor network traffic for DEX download
   - Monitor logcat for "OneList_Debug" and "OneList_Malware" tags
   - File system monitoring for temporary DEX files in cache directory

3. **Advanced Analysis:**
   - Reverse engineer obfuscated Base64 strings
   - Understand DexClassLoader usage pattern
   - Extract and analyze downloaded DEX file
   - Find flag method in NotificationService class

4. **Flag Extraction:**
   - Download DEX file from GitHub URL: `https://raw.githubusercontent.com/cynychwr/ctfs/main/rwyc/onelist/external/classes.dex`
   - Analyze with jadx/dex2jar: `jadx classes.dex`
   - Find `com.onelist.external.NotificationService.getFlag()` method
   - Extract flag: `CYWR{dynamic_code_loading_malware_wannabe}`

**Security Educational Value:**
- **DCL Detection:** Teaches how to identify dynamic code loading in Android malware
- **Manifest Analysis:** Shows importance of correlating manifest with actual code
- **Network Monitoring:** Demonstrates DEX download behavior
- **Joker Malware Simulation:** Realistic NotificationListener malware pattern
- **Advanced Obfuscation:** Multiple layers of hiding (Base64, reflection, string building)

**Modification Notes:**
- Update GitHub URL in Base64 encoded strings
- Change service class name and method names
- Modify obfuscation patterns (different encoding, reflection patterns)
- Update DEX file content and hosting location
- Can change trigger mechanism or count
- Update external DEX with new flag content

---

### **Flag 10: `CYWR{crypto_master_final_XXXXXXXX}`**
**Type:** AES with device-specific key derivation  
**Difficulty:** Expert (60+ minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/crypto/CryptoUtils.kt`
- **Trigger:** Automatic after Flag 6 completion
- **Method:** Device-specific key + AES encryption

**Discovery Method:**
1. Triggered automatically by Flag 6
2. Monitor logcat for final output
3. Analyze complex key derivation
4. Understand AES implementation

**Modification Notes:**
- Update AES encrypted data
- Can change trigger condition
- Keep device-specific derivation for expert-level challenge
- Hash portion is dynamic based on device

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
1. Build APK: `./gradlew assembleDebug`
2. Test static flags through decompilation
3. Test dynamic flags through app interaction
4. Verify encoding/decoding works correctly
5. Update solution guide

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