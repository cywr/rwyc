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

### **Flag 2: `CYWR{f0und_in_debug_build}`**
**Type:** Base64 encoded  
**Difficulty:** Easy (2 minutes)

**Implementation:**
- **File:** `/core/common/src/debug/res/values/strings.xml`
- **Line:** 5
- **Encoded:** `Q1lXUntmMHVuZF9pbl9kZWJ1Z19idWlsZH0=`
- **Code:** `<string name="debug_config">Q1lXUntmMHVuZF9pbl9kZWJ1Z19idWlsZH0=</string>`

**Discovery Method:**
- Found only in debug build resources
- Requires Base64 decoding

**Modification Notes:**
- To change flag: `echo -n "NEW_FLAG" | base64`
- Keep in debug resources to teach build variant analysis
- Maintain Base64 encoding for introduction to simple encoding

---

### **Flag 3: `CYWR{test_tags_are_useful}`**
**Type:** ROT13 with algorithm discovery  
**Difficulty:** Easy-Medium (5 minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/utils/TestTags.kt`
- **Encoded:** `PLJE{grfg_gntf_ner_hfrshy}`
- **Lines:** 6, 10-29

**Code Structure:**
```kotlin
const val InternalConfig = "PLJE{grfg_gntf_ner_hfrshy}"

fun getDecodedInternalConfig(): String {
    // ROT13 decoding algorithm
    for (char in encoded) {
        when {
            char in 'A'..'Z' -> {
                val shifted = ((char - 'A' + 13) % 26)
                decoded.append(('A' + shifted).toChar())
            }
            // ... rest of ROT13 implementation
        }
    }
}
```

**Usage:**
- **File:** `/feature/lists/src/main/kotlin/com/lolo/io/onelist/feature/lists/ListsScreen.kt`
- **Line:** 96
- **Code:** `val internalFlag = TestTags.getDecodedInternalConfig()`

**Discovery Method:**
1. Find encoded constant in TestTags
2. Analyze `getDecodedInternalConfig()` function
3. Reverse engineer ROT13 algorithm
4. Apply decoding

**Modification Notes:**
- To change flag: Apply ROT13 to new flag text
- Keep processing function for algorithm discovery learning
- Can modify the encoding algorithm but update processing function accordingly

---

### **Flag 4: `CYWR{m1gr4t10n_s3cr3ts}`**
**Type:** Base64→ROT13→Base64 chain  
**Difficulty:** Medium (10 minutes)

**Implementation:**
- **File:** `/core/database/src/main/kotlin/com/lolo/io/onelist/core/database/OneListDatabase.kt`
- **Encoded:** `RDF5S0hhZ2daSnFsQVVEa1pUNXNwbUF3cHdBMHAzMD0=`
- **Lines:** 28, 31-60

**Code Structure:**
```kotlin
const val MIGRATION_SIGNATURE = "RDF5S0hhZ2daSnFsQVVEa1pUNXNwbUF3cHdBMHAzMD0="

fun validateMigrationSignature(): String {
    // Step 1: Base64 decode
    val step1 = String(android.util.Base64.decode(encoded, android.util.Base64.DEFAULT))
    
    // Step 2: ROT13 decode
    val step2 = StringBuilder()
    for (char in step1) {
        // ROT13 transformation
    }
    
    // Step 3: Base64 decode again
    return String(android.util.Base64.decode(step2.toString(), android.util.Base64.DEFAULT))
}
```

**Usage:**
- **File:** `/core/database/src/main/kotlin/com/lolo/io/onelist/core/database/di/DaosModule.kt`
- **Line:** 11
- **Code:** `val signature = OneListDatabase.validateMigrationSignature()`

**Discovery Method:**
1. Find encoded constant in database class
2. Analyze `validateMigrationSignature()` function
3. Reverse engineer 3-step decoding process
4. Apply Base64→ROT13→Base64 chain

**Modification Notes:**
- To create new encoding: `base64(rot13(base64(flag)))`
- Keep 3-step process for multi-layer encoding education
- Update both constant and processing function if changing algorithm

---

### **Flag 5: `CYWR{manifest_permissions_matter}`**
**Type:** Hex encoded in AndroidManifest  
**Difficulty:** Medium (10 minutes)

**Implementation:**
- **File:** `/app/src/main/AndroidManifest.xml`
- **Location:** meta-data tag
- **Encoded:** `435957527b6d616e69666573745f7065726d697373696f6e735f6d617474657d`

**Code:**
```xml
<meta-data
    android:name="com.onelist.ctf.flag5"
    android:value="435957527b6d616e69666573745f7065726d697373696f6e735f6d617474657d" />
```

**Discovery Method:**
- Static analysis of AndroidManifest.xml
- Hex decoding of meta-data value

**Modification Notes:**
- To change flag: `echo -n "NEW_FLAG" | xxd -p | tr -d '\n'`
- Keep in manifest to teach Android manifest analysis
- Can change meta-data name but keep hex encoding

---

## 🏃 **Dynamic Analysis Flags (6-10)**

### **Flag 6: `CYWR{prefs_storage}`**
**Type:** XOR encrypted, runtime generation  
**Difficulty:** Medium-Hard (30 minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/repository/OneListRepositoryImpl.kt`
- **Lines:** 227-261
- **Trigger:** Create 3 lists, delete 2 lists
- **Storage:** SharedPreferences

**Code Structure:**
```kotlin
private fun checkFlag6Condition() {
    if (preferences.ctfListsCreated >= 3 && preferences.ctfListsDeleted >= 2) {
        preferences.ctfFlag6 = generateFlag6()
    }
}

private fun generateFlag6(): String {
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
- **File:** Same file, lines 95-102, 122-147
- **Methods:** `createList()`, `deleteList()`
- **Counters:** `ctfListsCreated`, `ctfListsDeleted`

**Discovery Method:**
1. Trigger condition through app usage
2. Find flag in SharedPreferences
3. Analyze generation algorithm
4. Reverse engineer XOR decryption

**Modification Notes:**
- Update `encryptedData` array for new flag
- Can change trigger conditions (list counts)
- Keep XOR encryption for dynamic analysis education
- To generate encrypted array: XOR each byte of flag with rotating key

---

### **Flag 7: `CYWR{room_e6_v64hfw4i}`**
**Type:** Context-derived encryption, database storage  
**Difficulty:** Hard (45 minutes)

**Implementation:**
- **File:** `/core/data/src/main/kotlin/com/lolo/io/onelist/core/data/repository/OneListRepositoryImpl.kt`
- **Lines:** 257-323
- **Trigger:** Create list "FLAG", add item "CYWR", mark done
- **Storage:** Room database (special entry with ID 999999)

**Code Structure:**
```kotlin
private suspend fun checkFlag7Condition(itemList: ItemList) {
    if (itemList.title.equals("FLAG", ignoreCase = true)) {
        val cyvrItem = itemList.items.find { 
            it.title.equals("CYWR", ignoreCase = true) && it.done 
        }
        if (cyvrItem != null) {
            val flagList = ItemList(title = generateFlag7(), id = 999999L)
            dao.upsert(flagList.toItemListEntity())
        }
    }
}

private fun generateFlag7(): String {
    val encryptedHex = "2f4e6d8a1c3b5e7f..." // Hex-encoded encrypted data
    val seed = context.applicationInfo.targetSdkVersion + context.packageName.length
    // Multi-key XOR with context-derived keys
}
```

**Discovery Method:**
1. Trigger condition through specific list/item creation
2. Find special database entry
3. Analyze generation algorithm
4. Reverse engineer context-derived decryption

**Modification Notes:**
- Update `encryptedHex` for new flag
- Can change trigger list/item names
- Keep context derivation for advanced dynamic analysis
- Seed derivation can be modified but update algorithm accordingly

---

### **Flag 8: `CYWR{dynamic_dex_loading_master}`**
**Type:** DexClassLoader with external DEX  
**Difficulty:** Very Hard (60+ minutes)

**Implementation:**
- **File:** `/feature/settings/src/main/kotlin/com/lolo/io/onelist/feature/settings/SettingsScreen.kt`
- **Lines:** Various (existing implementation)
- **Trigger:** Tap version number 10 times
- **Method:** External DEX loading + reflection

**Discovery Method:**
1. Trigger through UI interaction
2. Monitor network/DEX loading
3. Analyze fallback decryption
4. Understand reflection usage

**Modification Notes:**
- Update external DEX URL and content
- Can change trigger count
- Keep DexClassLoader for advanced technique education
- Requires hosting external DEX file

---

### **Flag 9: `CYWR{custom_polyalphabetic_cipher}`**
**Type:** Custom polyalphabetic cipher, logcat output  
**Difficulty:** Hard (60+ minutes)

**Implementation:**
- **File:** `/feature/lists/src/main/kotlin/com/lolo/io/onelist/feature/lists/ListScreenViewModel.kt`
- **Lines:** 226-271
- **Trigger:** Long-press app title 7 times
- **Output:** Android logcat (XOR encoded)

**Code Structure:**
```kotlin
private var flag9TapCount = 0

fun triggerFlag9() {
    flag9TapCount++
    if (flag9TapCount >= 7) {
        val flag = generateFlag9()
        val encodedFlag = flag.map { (it.code xor 42).toChar() }.joinToString("")
        Log.d("OneList_Debug", "System check: $encodedFlag")
    }
}

private fun generateFlag9(): String {
    val encryptedData = intArrayOf(0x4f, 0x5d, 0x53, ...) // Custom cipher
    val keys = intArrayOf(0x2A, 0x15, 0x33, 0x07, 0x1C) // Rotating keys
    // Polyalphabetic substitution with position-based transformations
}
```

**Discovery Method:**
1. Trigger through UI interaction
2. Monitor logcat output
3. Analyze custom cipher algorithm
4. Reverse engineer polyalphabetic decryption

**Modification Notes:**
- Update `encryptedData` array for new flag
- Can change trigger count or method
- Keep custom cipher for cryptography education
- Update both cipher data and key array for new flags

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
├── core/data/src/main/kotlin/.../TestTags.kt (Flag 3)
├── core/database/src/main/kotlin/.../OneListDatabase.kt (Flag 4)
└── app/src/main/AndroidManifest.xml (Flag 5)

Dynamic Flags:
├── core/data/src/main/kotlin/.../OneListRepositoryImpl.kt (Flags 6, 7)
├── feature/settings/src/main/kotlin/.../SettingsScreen.kt (Flag 8)
├── feature/lists/src/main/kotlin/.../ListScreenViewModel.kt (Flag 9)
└── core/data/src/main/kotlin/.../CryptoUtils.kt (Flag 10)

Usage/Triggers:
├── feature/lists/src/main/kotlin/.../ListsScreen.kt (Flag 3 usage)
├── core/database/src/main/kotlin/.../DaosModule.kt (Flag 4 usage)
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