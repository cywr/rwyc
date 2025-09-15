# OneList CTF - Complete Solution Guide

This document provides detailed solutions for all 10 flags in the OneList Android CTF challenge.

## Flag Format: `CYWR{...}`

---

## 🔍 **Static Analysis Flags (1-5)**

### **Flag 1: `CYWR{welcome_to_onelist_ctf}`**
**Difficulty:** Beginner  
**Location:** `app/src/main/res/values/strings.xml`

**Solution:**
```bash
# Method 1: Using strings command
strings app-debug.apk | grep CYWR

# Method 2: Using jadx
jadx app-debug.apk
# Navigate to Resources → res/values/strings.xml

# Method 3: Using apktool
apktool d app-debug.apk
cat OneList/res/values/strings.xml | grep CYWR
```

**Learning:** Basic string extraction is often the first step in APK analysis.

---

### **Flag 2: `CYWR{f0und_in_debug_build}`**
**Difficulty:** Easy  
**Location:** `core/common/src/debug/res/values/strings.xml`

**Solution:**
```bash
# The flag is Base64 encoded as: Q1lXUntmMHVuZF9pbl9kZWJ1Z19idWlsZH0=

# Using jadx - look in debug resources
jadx app-debug.apk
# Navigate to Resources → core.common.debug → res/values/strings.xml
# Look for debug_config string

# Using apktool
apktool d app-debug.apk
find OneList/ -name "strings.xml" | xargs grep -l debug_config

# Decode Base64
echo "Q1lXUntmMHVuZF9pbl9kZWJ1Z19idWlsZH0=" | base64 -d
```

**Learning:** Debug builds often contain encoded resources not present in release builds.

---

### **Flag 3: `CYWR{test_tags_are_useful}`**
**Difficulty:** Easy-Medium  
**Location:** `core/data/src/main/kotlin/com/lolo/io/onelist/core/data/utils/TestTags.kt`

**Solution:**
```bash
# The flag is ROT13 encoded as: PLJE{grfg_gntf_ner_hfrshy}

# Using jadx
jadx app-debug.apk
# Navigate to Source code → com.lolo.io.onelist.core.data.utils → TestTags
# Find the InternalConfig constant and the getDecodedInternalConfig() function

# Analyze the ROT13 decoding algorithm in getDecodedInternalConfig()
# The function shows ROT13 transformation: ((char - 'A' + 13) % 26)

# Decode ROT13
echo "PLJE{grfg_gntf_ner_hfrshy}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Alternative: Python ROT13
python3 -c "import codecs; print(codecs.decode('PLJE{grfg_gntf_ner_hfrshy}', 'rot13'))"
```

**Learning:** Algorithm discovery - analyze the processing function to understand the encoding method.

---

### **Flag 4: `CYWR{m1gr4t10n_s3cr3ts}`**
**Difficulty:** Medium  
**Location:** `core/database/src/main/kotlin/com/lolo/io/onelist/core/database/OneListDatabase.kt`

**Solution:**
```bash
# The flag is encoded with Base64→ROT13→Base64 chain
# Encoded as: RDF5S0hhZ2daSnFsQVVEa1pUNXNwbUF3cHdBMHAzMD0=

# Using jadx
jadx app-debug.apk
# Navigate to Source code → com.lolo.io.onelist.core.database → OneListDatabase
# Find MIGRATION_SIGNATURE constant and validateMigrationSignature() function

# Analyze the triple-decoding algorithm:
# Step 1: Base64 decode
# Step 2: ROT13 decode  
# Step 3: Base64 decode again

# Manual decoding:
echo "RDF5S0hhZ2daSnFsQVVEa1pUNXNwbUF3cHdBMHAzMD0=" | base64 -d
# Result: D1yKHaggZJqlAUDkZT5spmAwpwA0p30=

# ROT13 decode
echo "D1yKHaggZJqlAUDkZT5spmAwpwA0p30=" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Result: Q1lXUnttMWdyNHQxMG5fczNjcjN0c30=

# Base64 decode final
echo "Q1lXUnttMWdyNHQxMG5fczNjcjN0c30=" | base64 -d
# Result: CYWR{m1gr4t10n_s3cr3ts}
```

**Learning:** Multi-layer encoding chains require analyzing the processing algorithm step by step.

---

### **Flag 5: `CYWR{manifest_permissions_matter}`**
**Difficulty:** Medium  
**Location:** `app/src/main/AndroidManifest.xml`

**Solution:**
```bash
# The flag is hex encoded as: 435957527b6d616e69666573745f7065726d697373696f6e735f6d617474657d

# Using jadx
jadx app-debug.apk
# Navigate to Resources → AndroidManifest.xml
# Look for meta-data tags

# Using apktool
apktool d app-debug.apk
cat OneList/AndroidManifest.xml | grep meta-data

# Decode hex
echo "435957527b6d616e69666573745f7065726d697373696f6e735f6d617474657d" | xxd -r -p
```

**Learning:** AndroidManifest.xml can contain custom meta-data with encoded information.

---

## 🏃 **Dynamic Analysis Flags (6-10)**

### **Flag 6: `CYWR{prefs_storage}`**
**Difficulty:** Medium-Hard  
**Location:** SharedPreferences (runtime storage, XOR encrypted)

**Solution:**
```bash
# Trigger: Create 3 lists, delete 2 lists

# Install and run the app
adb install app-debug.apk

# Use the app to:
1. Create 3 lists (any names)
2. Delete 2 of those lists

# Check SharedPreferences (flag is XOR encrypted)
adb shell
cd /data/data/com.lolo.io.onelist.debug/shared_prefs/
cat *.xml

# The flag is generated dynamically using XOR encryption
# Analyze generateFlag6() function in OneListRepositoryImpl.kt
# Multi-byte XOR with package-name derived key

# Alternative: Using Frida to intercept the decrypted result
frida -U -l shared_prefs_monitor.js com.lolo.io.onelist.debug
```

**Frida Script Example:**
```javascript
Java.perform(function() {
    var SharedPrefs = Java.use("android.content.SharedPreferences");
    SharedPrefs.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        if (result && result.includes("CYWR")) {
            console.log("[+] Found flag in SharedPreferences: " + result);
        }
        return result;
    };
});
```

**Learning:** Runtime behavior can trigger flag storage in Android's SharedPreferences.

---

### **Flag 7: `CYWR{room_e6_v64hfw4i}`**
**Difficulty:** Hard  
**Location:** Room Database (SQLite, context-derived encryption)

**Solution:**
```bash
# Trigger: Create list named "FLAG", add item "CYWR", mark as complete

# Use the app to:
1. Create a new list named exactly "FLAG"
2. Add an item with text exactly "CYWR"
3. Mark that item as complete

# Check the database
adb shell
cd /data/data/com.lolo.io.onelist.debug/databases/
sqlite3 onelist_database

# Look for the dynamically generated flag entry
.tables
SELECT * FROM itemList WHERE id = 999999;
.quit

# The flag is generated by generateFlag7() function
# Uses hex-encoded XOR with context-derived keys (SDK version + package name)
# Analyze the decryption algorithm in OneListRepositoryImpl.kt
```

**Frida Script for Database Monitoring:**
```javascript
Java.perform(function() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
        console.log("[+] Database INSERT on table: " + table);
        console.log("[+] Values: " + values.toString());
        return this.insert(table, nullColumnHack, values);
    };
});
```

**Learning:** Database content can change based on specific user interactions.

---

### **Flag 8: `CYWR{dynamic_dex_loading_master}`**
**Difficulty:** Very Hard  
**Location:** External DEX file loaded via DexClassLoader

**Solution:**
```bash
# Trigger: Tap version number in settings 10 times

# Use the app:
1. Go to Settings
2. Tap the version number 10 times rapidly

# Monitor network traffic to find DEX URL
# The app tries to download: https://raw.githubusercontent.com/user/repo/main/hidden_flag.dex

# Monitor logcat for fallback behavior
adb logcat | grep -E "(CTF_FLAG_8|DexClassLoader|HiddenFlag)"

# If download fails, check the fallback decoding
# Double Base64 encoded: RFlXUntkbmVrdmFFWTJSeFl6TnFZakZJUVQwOQ==
echo "RFlXUntkbmVrdmFFWTJSeFl6TnFZakZJUVQwOQ==" | base64 -d | base64 -d
```

**Frida Script for DexClassLoader:**
```javascript
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log("[+] DexClassLoader loading: " + dexPath);
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
    
    var Class = Java.use("java.lang.Class");
    Class.forName.overload('java.lang.String').implementation = function(className) {
        if (className.includes("HiddenFlag") || className.includes("ctf")) {
            console.log("[+] Loading class: " + className);
        }
        return this.forName(className);
    };
});
```

**Learning:** Advanced Android techniques like DexClassLoader and reflection for runtime code loading.

---

### **Flag 9: `CYWR{custom_polyalphabetic_cipher}`**
**Difficulty:** Hard  
**Location:** Android logcat (custom polyalphabetic cipher)

**Solution:**
```bash
# Trigger: Long-press the app title 7 times

# Start monitoring logs
adb logcat | grep OneList_Debug &

# Use the app:
1. Go to the main screen
2. Long-press the "1List" title 7 times

# Look for encrypted output in logcat
# The flag uses a custom polyalphabetic cipher with key rotation

# Analyze generateFlag9() function in ListScreenViewModel.kt:
# - Custom substitution cipher with encrypted data array
# - Polyalphabetic substitution with rotating keys: [0x2A, 0x15, 0x33, 0x07, 0x1C]
# - Position-based transformations for letters vs special characters

# The encrypted data needs to be decrypted using the algorithm
# Then XOR encoded with key 42 before logging
```

**Frida Script for Log Monitoring:**
```javascript
Java.perform(function() {
    var Log = Java.use("android.util.Log");
    Log.d.implementation = function(tag, msg) {
        if (tag.includes("OneList") || msg.includes("System check")) {
            console.log("[+] Found debug log: " + tag + " : " + msg);
        }
        return this.d(tag, msg);
    };
});
```

**Learning:** Debugging logs can contain encoded flags that appear only after specific triggers.

---

### **Flag 10: `CYWR{crypto_master_final_XXXXXXXX}`**
**Difficulty:** Expert  
**Location:** AES encrypted with runtime key derivation

**Solution:**
```bash
# Trigger: After finding Flag 6, the app automatically triggers this

# This flag requires:
1. Flag 6 must be found first (creates 3 lists, deletes 2)
2. The key is derived from app signature + device info
3. Monitor logcat for the final flag

adb logcat | grep CTF_FINAL

# The flag format includes a device-specific hash:
# CYWR{crypto_master_final_ABCD1234}
```

**Frida Script for Crypto Monitoring:**
```javascript
Java.perform(function() {
    var CryptoUtils = Java.use("com.lolo.io.onelist.core.data.crypto.CryptoUtils");
    CryptoUtils.deriveKey.implementation = function(context) {
        var key = this.deriveKey(context);
        console.log("[+] Derived encryption key: " + key);
        return key;
    };
    
    var Log = Java.use("android.util.Log");
    Log.d.implementation = function(tag, msg) {
        if (tag === "CTF_FINAL") {
            console.log("[+] FINAL FLAG: " + msg);
        }
        return this.d(tag, msg);
    };
});
```

**Advanced Analysis:**
```bash
# Extract the CryptoUtils class for analysis
jadx app-debug.apk
# Navigate to com.lolo.io.onelist.core.data.crypto.CryptoUtils

# The key derivation uses:
# - App signature
# - Device manufacturer, model, fingerprint
# - Android SDK version and release
```

**Learning:** Advanced cryptography with runtime key derivation combining multiple device-specific factors.

---

## 📁 **External Resources**

For Flag 8 (DexClassLoader), you would need to create and host the external DEX file:

### `hidden_flag.dex` Content (Java source before compiling to DEX):
```java
package com.ctf;

public class HiddenFlag {
    public String revealFlag(String key) {
        if ("onelist_secret".equals(key)) {
            return "CYWR{dynamic_dex_loading_master}";
        }
        return "Invalid key";
    }
}
```

**Compile to DEX:**
```bash
# Compile Java to class
javac -cp $ANDROID_HOME/platforms/android-30/android.jar HiddenFlag.java

# Convert to DEX
$ANDROID_HOME/build-tools/30.0.3/dx --dex --output=hidden_flag.dex HiddenFlag.class

# Host on GitHub or your server
# URL should match: https://raw.githubusercontent.com/user/repo/main/hidden_flag.dex
```

---

## 🏆 **Complete Flag List**

1. `CYWR{welcome_to_onelist_ctf}`
2. `CYWR{f0und_in_debug_build}`
3. `CYWR{test_tags_are_useful}`
4. `CYWR{m1gr4t10n_s3cr3ts}`
5. `CYWR{manifest_permissions_matter}`
6. `CYWR{prefs_storage}` *(XOR encrypted)*
7. `CYWR{room_e6_v64hfw4i}` *(context-derived encryption)*
8. `CYWR{dynamic_dex_loading_master}`
9. `CYWR{custom_polyalphabetic_cipher}` *(custom cipher)*
10. `CYWR{crypto_master_final_XXXXXXXX}` *(device-specific hash)*

---

## 🛠️ **Tools Summary**

- **jadx**: Primary decompilation tool
- **apktool**: Resource extraction
- **adb**: Device interaction and monitoring
- **frida**: Runtime instrumentation
- **sqlite3**: Database inspection
- **strings/grep**: Text searching
- **base64/xxd**: Encoding/decoding utilities

**Congratulations on completing the OneList CTF! 🎉**