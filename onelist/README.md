# OneList CTF Resources

This directory contains resources and tools for the OneList Android CTF challenge.

## Structure

- `src/` - Java source code for the external DEX file
- `external/` - Output directory containing the generated DEX file
- `implementation.md` - Complete technical implementation guide for all flags
- `build-dex.sh` - Build script to compile and generate DEX file

## DEX Generation

To generate the external DEX file for Flag 9:

1. **Option 1: Use the build script (recommended)**
   ```bash
   ./build-dex.sh
   ```

2. **Option 2: Manual compilation**
   ```bash
   # Compile Java source
   mkdir -p temp && cp -r src/* temp/
   cd temp && javac -source 8 -target 8 com/onelist/external/NotificationService.java

   # Create JAR and convert to DEX
   jar cf notification_service.jar com/
   /Users/cynychwr/Library/Android/sdk/build-tools/34.0.0/d8 --output ../external notification_service.jar

   # Cleanup
   cd .. && rm -rf temp
   ```

## Source Code

- **File**: `src/com/onelist/external/NotificationService.java`
- **Class**: `NotificationService extends NotificationListenerService`
- **Package**: `com.onelist.external`
- **Flag**: `CYWR{dynamic_code_loading_malware_wannabe}`
- **Hidden Method**: `getFlag()`

## Output

- **File**: `external/classes.dex`
- **Contains**: NotificationService class with hidden flag
- **Size**: ~1,340 bytes
- **Format**: Dalvik dex file version 035

## Modification Workflow

1. **Edit source**: `src/com/onelist/external/NotificationService.java`
2. **Rebuild DEX**: `./build-dex.sh`
3. **Test**: `jadx external/classes.dex`

## GitHub Integration

Once committed to GitHub, the DEX file will be available at:
```
https://raw.githubusercontent.com/cynychwr/ctfs/main/rwyc/onelist/external/classes.dex
```

This URL is used in the OneList CTF's Dynamic Code Loading implementation for Flag 9 discovery.