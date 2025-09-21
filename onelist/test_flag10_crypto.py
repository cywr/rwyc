#!/usr/bin/env python3
"""
Flag 10 Crypto Testing Script
Test steganography and encryption for native CTF challenge

This script:
1. Implements LSB steganography for JPG images
2. Tests key generation and combination
3. Validates XOR encryption/decryption
4. Prepares images with embedded keys for the CTF
"""

import os
import sys
from PIL import Image
import hashlib
import random

# Flag and key configuration
FLAG = "CYWR{native_reverse_engineering}"
KEY_COMPONENT_SIZE = 8  # 8 bytes per component
NATIVE_KEY_COMPONENT = b'\x4E\x41\x54\x49\x56\x45\x43\x52'  # "NATIVECR" - will be hardcoded in C++

def log(message):
    """Log with prefix for clarity"""
    print(f"[Flag10Test] {message}")

def lsb_encode_data(image_path, data, output_path):
    """
    Encode data into image using LSB steganography
    Args:
        image_path: Source image file
        data: Bytes to encode
        output_path: Output image file
    """
    log(f"Encoding {len(data)} bytes into {image_path}")

    # Open image and convert to RGB
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    # Get image data as modifiable array
    pixels = list(img.getdata())

    # Convert data to binary string with length prefix
    data_binary = format(len(data), '08b')  # 8-bit length prefix
    data_binary += ''.join(format(byte, '08b') for byte in data)

    log(f"Binary data length: {len(data_binary)} bits (including length prefix)")

    if len(data_binary) > len(pixels):
        raise ValueError(f"Image too small for data. Need {len(data_binary)} bits, have {len(pixels)}")

    # Encode data in LSB of red channel only (more reliable)
    modified_pixels = []

    for i, (r, g, b) in enumerate(pixels):
        if i < len(data_binary):
            # Modify red channel LSB only
            new_r = (r & 0xFE) | int(data_binary[i])
            modified_pixels.append((new_r, g, b))
        else:
            modified_pixels.append((r, g, b))

    # Create new image and save as PNG (lossless)
    new_img = Image.new('RGB', img.size)
    new_img.putdata(modified_pixels)

    # Save as PNG for lossless compression
    base_name = os.path.splitext(output_path)[0]
    png_output = base_name + '.png'
    new_img.save(png_output, 'PNG')

    log(f"Image saved to {png_output} (converted to PNG for lossless compression)")

def lsb_decode_data(image_path, expected_length=None):
    """
    Decode data from image using LSB steganography
    Args:
        image_path: Image file with encoded data
        expected_length: Expected number of bytes (for validation)
    Returns:
        Decoded bytes
    """
    log(f"Decoding data from {image_path}")

    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())

    # Extract bits from red channel LSBs only
    binary_data = ""
    for r, g, b in pixels:
        binary_data += str(r & 1)  # Red LSB only

    # First 8 bits contain the length
    if len(binary_data) < 8:
        raise ValueError("Image too small to contain length prefix")

    length_bits = binary_data[:8]
    data_length = int(length_bits, 2)

    log(f"Found length prefix: {data_length} bytes")

    # Extract the actual data
    data_bits = binary_data[8:8 + (data_length * 8)]

    if len(data_bits) < data_length * 8:
        raise ValueError(f"Not enough data bits. Expected {data_length * 8}, got {len(data_bits)}")

    # Convert binary to bytes
    decoded_bytes = bytearray()
    for i in range(0, len(data_bits), 8):
        byte_str = data_bits[i:i+8]
        decoded_bytes.append(int(byte_str, 2))

    log(f"Decoded {len(decoded_bytes)} bytes")

    if expected_length and len(decoded_bytes) != expected_length:
        log(f"Warning: Expected {expected_length} bytes, got {len(decoded_bytes)}")

    return bytes(decoded_bytes)

def generate_key_component():
    """Generate a random 8-byte key component"""
    return os.urandom(KEY_COMPONENT_SIZE)

def xor_encrypt(data, key):
    """XOR encrypt data with key (repeating key as needed)"""
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % len(key)])
    return bytes(result)

def combine_keys(key1, key2, key3):
    """Combine three key components using XOR"""
    combined = bytearray(KEY_COMPONENT_SIZE)
    for i in range(KEY_COMPONENT_SIZE):
        combined[i] = key1[i] ^ key2[i] ^ key3[i]
    return bytes(combined)

def test_steganography():
    """Test LSB steganography encode/decode"""
    log("=== Testing LSB Steganography ===")

    # Test data
    test_data = b"TESTKEY1"

    # Test with background image
    if not os.path.exists("assets/background.jpg"):
        log("ERROR: assets/background.jpg not found!")
        return False

    # Encode test data
    lsb_encode_data("assets/background.jpg", test_data, "test_encoded.jpg")

    # Decode test data (PNG file will be created)
    decoded = lsb_decode_data("test_encoded.png", len(test_data))

    # Verify
    if decoded == test_data:
        log("✓ Steganography test PASSED")
        # Clean up test files
        if os.path.exists("test_encoded.png"):
            os.remove("test_encoded.png")
        return True
    else:
        log(f"✗ Steganography test FAILED: {decoded} != {test_data}")
        return False

def test_encryption():
    """Test XOR encryption/decryption"""
    log("=== Testing XOR Encryption ===")

    # Test key and data
    test_key = b"TESTKEY8"
    test_data = FLAG.encode('utf-8')

    # Encrypt
    encrypted = xor_encrypt(test_data, test_key)
    log(f"Encrypted: {encrypted.hex()}")

    # Decrypt
    decrypted = xor_encrypt(encrypted, test_key)

    # Verify
    if decrypted.decode('utf-8') == FLAG:
        log("✓ Encryption test PASSED")
        return True
    else:
        log(f"✗ Encryption test FAILED: {decrypted} != {FLAG}")
        return False

def prepare_images():
    """Prepare images with embedded key components"""
    log("=== Preparing Images for CTF ===")

    # Generate key components
    key1 = generate_key_component()  # For background.jpg
    key2 = generate_key_component()  # For icon_large.jpg
    key3 = NATIVE_KEY_COMPONENT      # Hardcoded in native library

    log(f"Key component 1 (background.jpg): {key1.hex()}")
    log(f"Key component 2 (icon_large.jpg): {key2.hex()}")
    log(f"Key component 3 (native): {key3.hex()}")

    # Combine keys
    final_key = combine_keys(key1, key2, key3)
    log(f"Combined key: {final_key.hex()}")

    # Encrypt flag
    flag_bytes = FLAG.encode('utf-8')
    encrypted_flag = xor_encrypt(flag_bytes, final_key)
    log(f"Encrypted flag: {encrypted_flag.hex()}")

    # Verify encryption works
    decrypted_test = xor_encrypt(encrypted_flag, final_key)
    if decrypted_test.decode('utf-8') != FLAG:
        log("✗ ERROR: Encryption verification failed!")
        return False

    log("✓ Encryption verification passed")

    # Embed keys in images
    try:
        # Create output directory
        os.makedirs("prepared_assets", exist_ok=True)

        # Embed key1 in background.jpg
        lsb_encode_data("assets/background.jpg", key1, "prepared_assets/background.jpg")

        # Embed key2 in icon_large.jpg
        lsb_encode_data("assets/icon_large.jpg", key2, "prepared_assets/icon_large.jpg")

        log("✓ Images prepared successfully")

        # Write key information for native implementation
        with open("key_components.txt", "w") as f:
            f.write("Key Components for Native Implementation\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Key 1 (background.jpg): {key1.hex()}\n")
            f.write(f"Key 2 (icon_large.jpg): {key2.hex()}\n")
            f.write(f"Key 3 (native code): {key3.hex()}\n\n")
            f.write(f"Combined Key: {final_key.hex()}\n\n")
            f.write(f"Flag: {FLAG}\n")
            f.write(f"Encrypted Flag: {encrypted_flag.hex()}\n\n")
            f.write("C++ Array for encrypted flag:\n")
            f.write("const unsigned char encrypted_flag[] = {\n")
            f.write("    " + ", ".join(f"0x{b:02x}" for b in encrypted_flag) + "\n")
            f.write("};\n\n")
            f.write("C++ Array for native key component:\n")
            f.write("const unsigned char native_key[] = {\n")
            f.write("    " + ", ".join(f"0x{b:02x}" for b in key3) + "\n")
            f.write("};\n")

        log("✓ Key information written to key_components.txt")
        return True

    except Exception as e:
        log(f"✗ ERROR preparing images: {e}")
        return False

def verify_prepared_images():
    """Verify that prepared images contain correct key data"""
    log("=== Verifying Prepared Images ===")

    try:
        # Read key information
        with open("key_components.txt", "r") as f:
            content = f.read()

        # Extract expected keys
        lines = content.split('\n')
        key1_hex = None
        key2_hex = None

        for line in lines:
            if "Key 1 (background.jpg):" in line:
                key1_hex = line.split(": ")[1]
            elif "Key 2 (icon_large.jpg):" in line:
                key2_hex = line.split(": ")[1]

        if not key1_hex or not key2_hex:
            log("✗ Could not extract expected keys")
            return False

        key1_expected = bytes.fromhex(key1_hex)
        key2_expected = bytes.fromhex(key2_hex)

        # Decode from images (PNG files)
        key1_decoded = lsb_decode_data("prepared_assets/background.png", KEY_COMPONENT_SIZE)
        key2_decoded = lsb_decode_data("prepared_assets/icon_large.png", KEY_COMPONENT_SIZE)

        # Verify
        if key1_decoded == key1_expected and key2_decoded == key2_expected:
            log("✓ Image verification PASSED")
            return True
        else:
            log("✗ Image verification FAILED")
            log(f"  Key1 expected: {key1_expected.hex()}")
            log(f"  Key1 decoded:  {key1_decoded.hex()}")
            log(f"  Key2 expected: {key2_expected.hex()}")
            log(f"  Key2 decoded:  {key2_decoded.hex()}")
            return False

    except Exception as e:
        log(f"✗ Verification error: {e}")
        return False

def main():
    """Main testing function"""
    log("Starting Flag 10 Crypto Tests")
    log("=" * 50)

    # Check if required files exist
    if not os.path.exists("assets"):
        log("ERROR: assets/ directory not found!")
        log("Please ensure assets/background.jpg and assets/icon_large.jpg exist")
        return 1

    if not os.path.exists("assets/background.jpg"):
        log("ERROR: assets/background.jpg not found!")
        return 1

    if not os.path.exists("assets/icon_large.jpg"):
        log("ERROR: assets/icon_large.jpg not found!")
        return 1

    # Run tests
    tests_passed = 0
    total_tests = 4

    if test_steganography():
        tests_passed += 1

    if test_encryption():
        tests_passed += 1

    if prepare_images():
        tests_passed += 1

    if verify_prepared_images():
        tests_passed += 1

    # Summary
    log("=" * 50)
    log(f"Tests completed: {tests_passed}/{total_tests} passed")

    if tests_passed == total_tests:
        log("✓ ALL TESTS PASSED - Images ready for CTF!")
        log("")
        log("Next steps:")
        log("1. Copy prepared_assets/*.jpg to OneList-ctf/app/src/main/assets/")
        log("2. Use key_components.txt to implement native C++ code")
        log("3. Build and test the native library")
        return 0
    else:
        log("✗ Some tests failed - please check the errors above")
        return 1

if __name__ == "__main__":
    sys.exit(main())