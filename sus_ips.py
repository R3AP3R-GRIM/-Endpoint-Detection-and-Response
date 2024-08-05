import psutil
import logging
import time
from flask import Flask, request, jsonify
import threading

app = Flask(__name__)

# Configure logger
logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG for more detailed logging
logger = logging.getLogger(__name__)

# Global set for storing suspicious IPs
suspicious_ips = set()

def analyze_network_traffic(suspicious_ips):
    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    remote_address = conn.raddr
                    if remote_address and remote_address[0] in suspicious_ips:
                        logger.warning(f"Suspicious connection detected: {remote_address[0]}")
        
            time.sleep(1)  # Sleep for 1 second before checking again
        
        except Exception as e:
            logger.error(f"Error while analyzing network traffic: {e}")

# Endpoint to add suspicious IP
@app.route('/add_suspicious_ip', methods=['POST'])
def add_suspicious_ip():
    data = request.get_json()
    new_ip = data.get('ip')
    
    if new_ip:
        suspicious_ips.add(new_ip)
        logger.warning(f"Added {new_ip} to suspicious IPs.")
        return jsonify({'message': f"Added {new_ip} to suspicious IPs."}), 200
    else:
        return jsonify({'error': 'Invalid IP provided.'}), 400

# Function to start the network traffic analysis in a separate thread
def start_analysis():
    analysis_thread = threading.Thread(target=analyze_network_traffic, args=(suspicious_ips,))
    analysis_thread.start()

if __name__ == '__main__':
    start_analysis()  # Start the network analysis thread
    app.run(debug=True)

import psutil
import logging
import time
from flask import Flask, request, jsonify
import threading
import subprocess

app = Flask(__name__)

# Configure logger
logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG for more detailed logging
logger = logging.getLogger(__name__)

# Global set for storing suspicious IPs
suspicious_ips = set()

def analyze_network_traffic(suspicious_ips):
    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    remote_address = conn.raddr
                    if remote_address and remote_address[0] in suspicious_ips:
                        logger.warning(f"Suspicious connection detected: {remote_address[0]}")
                        block_ip_windows(remote_address[0])  # Block the suspicious IP on Windows
        
            time.sleep(1)  # Sleep for 1 second before checking again
        
        except Exception as e:
            logger.error(f"Error while analyzing network traffic: {e}")

def block_ip_windows(ip):
    # Function to block IP using Windows Firewall
    try:
        # Check if the IP is already blocked
        check_command = f'netsh advfirewall firewall show rule name="Block IP {ip}"'
        result = subprocess.run(check_command, capture_output=True, text=True, shell=True)
        
        if "No rules match the specified criteria." in result.stdout:
            # Create new block rule
            block_command = f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in interface=any action=block remoteip={ip}'
            subprocess.run(block_command, check=True, shell=True)
            logger.warning(f"Blocked IP address {ip} using Windows Firewall.")
        else:
            logger.warning(f"IP address {ip} is already blocked.")
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP address {ip}: {e}")

# Endpoint to add suspicious IP
@app.route('/add_suspicious_ip', methods=['POST'])
def add_suspicious_ip():
    data = request.get_json()
    new_ip = data.get('ip')
    
    if new_ip:
        suspicious_ips.add(new_ip)
        logger.warning(f"Added {new_ip} to suspicious IPs.")
        return jsonify({'message': f"Added {new_ip} to suspicious IPs."}), 200
    else:
        return jsonify({'error': 'Invalid IP provided.'}), 400

# Function to start the network traffic analysis in a separate thread
def start_analysis():
    analysis_thread = threading.Thread(target=analyze_network_traffic, args=(suspicious_ips,))
    analysis_thread.start()

if __name__ == '__main__':
    start_analysis()  # Start the network analysis thread
    app.run(debug=True)
