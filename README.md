# Endpoint Detection and Response

This repository contains an Endpoint Detection and Response (EDR) system designed to monitor, detect, and respond to suspicious activities on endpoints in a network. The system includes various scripts and configuration files to perform these tasks.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Scripts](#scripts)
- [Contributing](#contributing)
- [License](#license)

## Features

- Monitor network traffic for suspicious activities.
- Detect and alert on potential security threats.
- Disable network interfaces in case of detected threats.
- Customizable thresholds for network activities.
- Maintain a list of suspicious IP addresses.
- Generate alerts based on resource usage.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/your-username/Endpoint-Detection-and-Response.git
    ```

2. Navigate to the project directory:
    ```sh
    cd Endpoint-Detection-and-Response
    ```

3. Install required dependencies (if any).

## Usage

To use the EDR system, run the main script `EDR.py`:
```sh
python EDR.py
```

## Configuration

The behavior of the EDR system can be customized using the `config.ini` file. This file contains various settings such as network thresholds, alert configurations, and other parameters. 

Example `config.ini`:
```ini
[Network]
threshold = 1000

[Alerts]
email = alert@example.com

[IPs]
suspicious_ips = sus_ips.txt
```

## Scripts

### EDR.py

The main script that orchestrates the monitoring, detection, and response processes.

### disablenetwrok.py

A script to disable network interfaces when a threat is detected.

### resource_alerts.py

Monitors system resource usage and generates alerts if usage exceeds defined thresholds.

### sus_ips.py

Maintains and processes a list of suspicious IP addresses.

### threshold_network.py

Checks network traffic against predefined thresholds and triggers alerts or actions if thresholds are exceeded.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature-name`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature/your-feature-name`.
5. Open a pull request.

## License

This project is licensed under the CC BY-NC-SA 4.0 License - see the [LICENSE](LICENSE) file for details.
