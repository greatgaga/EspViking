#!/usr/bin/env python3
import os
import sys
import subprocess

MIN_PY = (3, 6)
# Flash offsets for ESP32
FLASH_OFFSETS = {
    'bootloader': '0x1000',
    'partitions': '0x8000',
    'firmware': '0x10000'
}

def ensure_python_version():
    if sys.version_info < MIN_PY:
        sys.exit(f"❌ Python {MIN_PY[0]}.{MIN_PY[1]} or higher is required.")

def install_dependencies():
    print("📦 Installing esptool and tqdm (optional progress bar)...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "--upgrade", 
            "esptool", "tqdm"
        ])
    except subprocess.CalledProcessError:
        sys.exit("❌ Failed to install dependencies. Please check your Python/pip setup.")

def find_binary(name):
    """
    Locate a binary under the firmware directory.
    name: 'bootloader', 'partitions', or 'firmware'
    """
    root = os.path.dirname(__file__)
    filename = 'espviking.bin' if name == 'firmware' else f"{name}.bin"
    path = os.path.join(root, 'firmware', filename)
    if not os.path.isfile(path):
        sys.exit(f"❌ {name.capitalize()} binary not found at {path}. Please build and copy it first.")
    return path

def prompt_connect():
    input("🔌 Connect your ESP32 and press ENTER to continue...")

def flash_all():
    # Locate binaries
    bootloader = find_binary('bootloader')
    partitions = find_binary('partitions')
    firmware = find_binary('firmware')

    cmd = [
        sys.executable, '-m', 'esptool',
        '--chip', 'esp32',
        '--baud', '460800',
        '--before', 'default_reset',
        '--after', 'hard_reset',
        'write_flash', '-z',
        FLASH_OFFSETS['bootloader'], bootloader,
        FLASH_OFFSETS['partitions'], partitions,
        FLASH_OFFSETS['firmware'], firmware
    ]
    print("⚡ Flashing: bootloader, partitions, firmware...")
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        sys.exit("❌ Flashing failed. Ensure your ESP32 is in bootloader mode and correctly connected.")

def main():
    ensure_python_version()
    print("🚀 Starting EspViking Installer")
    install_dependencies()
    prompt_connect()
    flash_all()
    print("✅ EspViking successfully flashed! Enjoy pentesting with your ESP32.")

if __name__ == '__main__':
    main()