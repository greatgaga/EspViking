EspViking
=========

Firmware for the ESP32 designed for Wi-Fi pentesting, inspired by the aesthetic and themes of Mr. Robot.  
NOTE: Use this tool responsibly and ethically.

----------------------------------------
QUICK FLASH (NO BUILD REQUIRED)
----------------------------------------

If you just want to flash the firmware to your ESP32 and try it out, there's no need to install a full development environment.

REQUIREMENTS:
- Python 3.6 or higher
- A USB-connected ESP32 board

INSTALLATION STEPS:

1. Clone the repository:

   git clone https://github.com/greatgaga/EspViking.git
   cd EspViking

2. Run the installer:

   python installer.py

   This will:
   - Install esptool (if not already installed)
   - Flash the precompiled firmware to your ESP32
   - Prompt you to connect the board

----------------------------------------
FULL DEVELOPMENT SETUP (OPTIONAL)
----------------------------------------

If you want to change the code, add features, or rebuild the firmware:

1. Install Visual Studio Code: https://code.visualstudio.com/download
2. Install the C/C++ extension for VS Code
3. Install the PlatformIO extension in VS Code
4. Install Git: https://git-scm.com/downloads
5. Clone this repository and open it in VS Code
6. Make sure the correct board is set in the platformio.ini file (default is esp32wroom32)
7. Build the project using PlatformIO: "Build" or run `pio run`

NOTE:
- PlatformIO will automatically install all required libraries on the first run (requires internet access).
- Make sure you’re using a supported ESP32 board and that it’s correctly selected in the platformio.ini file.

----------------------------------------
FIRMWARE CONFIGURATION
----------------------------------------

Before flashing the firmware (whether prebuilt or custom), make sure you:

- Edit config.h to set your Wi-Fi SSID and password
- Optionally modify the wordlists inside the "data" directory

----------------------------------------
HOW TO USE
----------------------------------------

Only thing you have to do is to turn on the ESP32 and connect to its web page (in browser "search" its 
local IP address and it will take you to its web page)

----------------------------------------
ACKNOWLEDGEMENTS
----------------------------------------

Huge thanks to the Bjorn repo for a lot of inspiration in this project: https://github.com/infinition/Bjorn/

----------------------------------------
DISCLAIMER
----------------------------------------

This project is for educational and ethical use only.  
Do not use this tool on any network you do not have explicit permission to test.  
You are solely responsible for any actions taken with this code.

Happy hacking. 👾
