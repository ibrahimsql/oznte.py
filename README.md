# Oznte.py 🛠️📡

Welcome to **Oznte.py**, the ultimate wireless attack tool designed for network security professionals and enthusiasts. With this powerful Python-based tool, you can conduct a variety of wireless network assessments, including vulnerability scanning and packet injection. 🔍🚀

## Features ✨

- **Wireless Vulnerability Scanning** 🔒: Detect potential weaknesses in your wireless network.
- **Packet Injection** 💉: Perform advanced attacks to test network resilience.
- **Network Sniffing** 📶: Capture and analyze network traffic to uncover hidden vulnerabilities.
- **Comprehensive Reporting** 📑: Generate detailed reports to document findings and enhance security.
- **User-Friendly Interface** 🖥️: Simple and intuitive command-line interface.

## Installation 🚀

Get started with **Oznte.py** by following these steps:

1. **Clone the Repository**:

   ```
   git clone https://github.com/ibrahimsql/oznte.py.git

**Navigate to the Project Directory:**
cd oznte.py

#### Install Dependencies:
**Make sure you have Python 3.x installed. Install the required Python libraries with:**
pip install -r requirements.txt

## Usage 🎯
To run Oznte.py, use the following command:
**python oznte.py [options]**

## Options 🛠️
-s <service>: Specify the service to scan (e.g., wifi, bluetooth).
-t <duration>: Set the scan duration in seconds.
-v: Enable verbose output for detailed information.
-o <file>: Save results to a specified file.
-a <address>: Define the IP address or network range to scan (e.g., 192.168.1.0/24).
-p <port>: Target specific ports (e.g., -p 80,443).
-r <rate>: Set the packet sending rate (e.g., -r 100 packets per second).
-l <logfile>: Specify a log file to capture detailed execution logs.
-f <format>: Choose the output format (e.g., json, xml).
-x <proxy>: Configure a proxy server for routing scan traffic.
-n <threads>: Set the number of threads for scanning (e.g., -n 10).
-c <config>: Load settings from a configuration file.
-i <interface>: Specify the network interface to use (e.g., eth0, wlan0).
-d <debug>: Enable debug mode for troubleshooting.
-u <username>: Provide a username for services requiring authentication.
-k <password>: Provide a password for services requiring authentication.
-m <mode>: Set the scanning mode (e.g., quick, full).
-e <exclude>: Exclude specific IP addresses or ranges from scanning.
-h: Display help and usage information.

### Examples 🌟
**Basic Wireless Scan:**
1. python oznte.py -s wifi -t 30 -v -o scan_results.txt
This command performs a 30-second scan of the wifi service, enables verbose output, and saves results to scan_results.txt.

2. Network Range Scan with Specific Ports:
python oznte.py -s wifi -a 192.168.1.0/24 -p 80,443 -t 60 -o range_scan_results.txt
This command scans the wifi service over the 192.168.1.0/24 network range, targets ports 80 and 443, and saves the results to range_scan_results.txt for 60 seconds

3.High Rate Packet Injection:
python oznte.py -s wifi -r 500 -t 20 -v -o packet_injection_results.txt
This command performs packet injection with a rate of 500 packets per second for 20 seconds, provides verbose output, and saves the results to packet_injection_results.txt.

4.Scan with Proxy and Custom Interface:
python oznte.py -s bluetooth -x http://proxy.example.com:8080 -i wlan0 -t 15 -o proxy_scan_results.txt
This command scans the bluetooth service using a proxy server and the wlan0 network interface for 15 seconds, and saves the results to proxy_scan_results.txt.

5.Verbose Mode with Debug Logs and Configuration File:
python oznte.py -s wifi -t 45 -v -d -c config.json -o detailed_scan_results.txt
This command performs a 45-second scan with verbose output and debug logs, uses settings from config.json, and saves results to detailed_scan_results.txt.

## Contributing 🤝

We welcome contributions to **Oznte.py**! If you have suggestions or improvements, please:

- **Fork the Repository**: [Fork Here](https://github.com/ibrahimsql/oznte.py/fork)
- **Submit a Pull Request**: Open a pull request with your changes.
- **Open an Issue**: Report any bugs or request features [here](https://github.com/ibrahimsql/oznte.py/issues).

## Support 💬

If you need help or have questions, feel free to reach out:

- **GitHub Issues**: [Open an Issue](https://github.com/ibrahimsql/oznte.py/issues)
- **Email**: contact@example.com
- **Twitter**: [@ibrahimsql](https://twitter.com/ibrahimsql)

## License 📜

**Oznte.py** is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact 📧

For any questions or support, please reach out to [ibrahimsql](https://github.com/ibrahimsql) on GitHub.

---

**Oznte.py** is your go-to solution for advanced wireless network security testing. Explore its features and enhance your security measures today! 🔐🔧



