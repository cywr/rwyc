#!/bin/bash

# Build script for NotificationListener DEX file
# This script compiles the Java source and converts it to DEX format

set -e  # Exit on any error

echo "Building NotificationListener DEX file..."

# Clean and create build directory for compiled output
rm -rf _build 2>/dev/null || true
mkdir -p _build

# Compile Java source with Android SDK directly from src
echo "Compiling Java source..."
ANDROID_JAR="/Users/cynychwr/Library/Android/sdk/platforms/android-34/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
    echo "❌ Error: Android SDK not found at $ANDROID_JAR"
    echo "Please install Android SDK or update the path"
    exit 1
fi
javac -cp "$ANDROID_JAR" -source 8 -target 8 -d _build src/com/onelist/external/NotificationService.java

# Create JAR file from compiled classes
echo "Creating JAR file..."
cd _build
jar cf notification_service.jar com/

# Convert JAR to DEX using Android SDK d8 tool
echo "Converting JAR to DEX..."
/Users/cynychwr/Library/Android/sdk/build-tools/34.0.0/d8 --output ../external notification_service.jar

# Go back to parent directory
cd ..

# Check if DEX file was created
if [ -f "external/classes.dex" ]; then
    echo "✅ DEX file created: external/classes.dex"
    echo "📊 File size: $(wc -c < external/classes.dex) bytes"
    echo "🔍 File type: $(file external/classes.dex)"
else
    echo "❌ Error: DEX file was not created"
    exit 1
fi

# Clean up build directory
rm -rf _build

echo "🎉 Build completed successfully!"
echo ""
echo "To modify the class:"
echo "1. Edit: src/com/onelist/external/NotificationService.java"
echo "2. Run: ./build-dex.sh"
echo "3. Test: jadx external/classes.dex"