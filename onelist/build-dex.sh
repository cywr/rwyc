#!/bin/bash

# Build script for NotificationListener DEX file
# This script compiles the Java source and converts it to DEX format

set -e  # Exit on any error

echo "Building NotificationListener DEX file..."

# Clean and create temp directory
rm -rf temp 2>/dev/null || true
mkdir -p temp

# Copy source files to temp directory
cp -r src/* temp/

# Navigate to temp directory
cd temp

# Compile Java source with Java 8 compatibility
echo "Compiling Java source..."
javac -source 8 -target 8 com/onelist/external/NotificationService.java

# Create JAR file
echo "Creating JAR file..."
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

# Clean up temp directory
rm -rf temp

echo "🎉 Build completed successfully!"
echo ""
echo "To modify the class:"
echo "1. Edit: src/com/onelist/external/NotificationService.java"
echo "2. Run: ./build-dex.sh"
echo "3. Test: jadx external/classes.dex"