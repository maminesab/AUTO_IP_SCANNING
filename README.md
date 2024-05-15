# IP Scanner

This Python script provides a simple graphical user interface for scanning IP addresses using the VirusTotal API. It allows users to monitor the reputation of IP addresses by retrieving data such as last analysis statistics.

## Prerequisites

- Python 3.x
- tkinter library (usually included in Python installations)
- requests library (install via `pip install requests`)

## Getting Started

1. Clone or download the repository to your local machine.
2. Ensure you have a valid VirusTotal API key. If you don't have one, sign up for an account at [VirusTotal](https://www.virustotal.com/) and obtain your API key.
3. Install the required dependencies using pip:
4. Configure your API key by editing the `config.ini` file and adding your API key under the `[API]` section.

## Usage

1. Run the `main.py` script.
2. The application window will open, displaying a text area for output.
3. Copy an IP address to the clipboard.
4. The script will automatically detect the copied IP address and fetch its data from VirusTotal.
5. The fetched data, including the IP address and its last analysis stats, will be displayed in the text area.

## Use Case

This script is particularly useful in scenarios where there is a need to deal with a large volume of IP addresses. When working in a network security operations center (SOC) or handling network security for an organization, analysts often need to quickly assess the reputation of various IP addresses. Automating the process of querying VirusTotal for IP address reviews streamlines this workflow, allowing analysts to focus on analyzing the results rather than manually fetching data for each IP address.

## Features

- Automatic detection of IP addresses copied to the clipboard.
- Configuration option to set the scan interval.
- Option to configure the VirusTotal API key from within the application.

## Screenshots

![Screenshot](/succesful_run.png)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
