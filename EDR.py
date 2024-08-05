import win32file
import win32con
import threading
import json
from elasticsearch import Elasticsearch
import psutil
import time
import socket
from datetime import datetime
import subprocess
import requests
import hashlib
import warnings
import logging
import os
from flask import Flask, request, jsonify
import configparser
import re

warnings.filterwarnings('ignore')

script_dir = os.path.dirname(os.path.realpath(__file__))
config_file_path = os.path.join(script_dir, 'config.ini')
config = configparser.ConfigParser()
if os.path.exists(config_file_path):
    config.read(config_file_path)
    
    log_file_path = config['paths']['LOG_FILE_PATH']
    logging_level = int(config['logging']['LOGGING_LEVEL'])
    ELASTICSEARCH_URL = config['Elasticsearch']['URL']
    ELASTICSEARCH_USERNAME = config['Elasticsearch']['Username']
    ELASTICSEARCH_PASSWORD = config['Elasticsearch']['Password']

# Set up logging
logging.basicConfig(filename=log_file_path, level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging_level)

def setup_elasticsearch():
    try:
        # Elasticsearch setup
        es = Elasticsearch(
            [ELASTICSEARCH_URL],
            basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
            verify_certs=False
        )

        # Create index if it doesn't exist
        index_name = 'system_info'
        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name)
            logger.info(f"Created index: {index_name}")

        return es, index_name
    except Exception as e:
        logger.error(f"Error setting up Elasticsearch: {e}")
        return None, None

es, index_name = setup_elasticsearch()

app = Flask(__name__)

def watch_directory(directory_path):
    try:
        FILE_LIST_DIRECTORY = 0x0001
        hDir = win32file.CreateFile(
            directory_path,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        while True:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )

            for action, file in results:
                try:
                    event_name = {
                        1: "added",
                        2: "removed",
                        3: "modified",
                        4: "renamed (old one)",
                        5: "renamed (new one)"
                    }.get(action, "unknown")

                    full_path = f"{directory_path}\\{file}"
                    timestamp = datetime.now().isoformat()
                    event = {"file_event": event_name, "file_action": action, "file_path": full_path, "timestamp": timestamp, "module": "directory_change"}
                    json_data = json.dumps(event, indent=2)
                    print(json_data)

                    try:
                        if es:
                            es.index(index=index_name, body=event)
                            logger.info(f"Indexed file event: {event}")
                    except Exception as e:
                        logger.error(f"Failed to index file event: {e}")
                except Exception as e:
                    logger.error(f"Error processing file event: {e}")

            time.sleep(1)  # Adjust sleep time based on your monitoring frequency
    except Exception as e:
        logger.error(f"Error watching directory {directory_path}: {e}")

def monitor_open_ports():
    try:
        while True:
            connections = psutil.net_connections()
            for conn in connections:
                try:
                    if conn.status == 'LISTEN':
                        try:
                            service = socket.getservbyport(conn.laddr.port)
                        except Exception:
                            service = 'Unknown'
                        print(f"Port {conn.laddr.port} is open. Service: {service}")
                        doc = {
                            "port": conn.laddr.port,
                            "module": "port_checker",
                            "service": service,
                            "status": "open",
                            "timestamp": datetime.now().isoformat()
                        }

                        try:
                            if es:
                                es.index(index=index_name, body=doc)
                                logger.info(f"Indexed open port: {doc}")
                        except Exception as e:
                            logger.error(f"Failed to index open port: {e}")
                except Exception as e:
                    logger.error(f"Error processing open port: {e}")

            time.sleep(60)  # Adjust sleep time based on your monitoring frequency
    except Exception as e:
        logger.error(f"Error monitoring open ports: {e}")

def calculate_hash(file_path, hash_algorithm):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            if hash_algorithm == "md5":
                return hashlib.md5(data).hexdigest()
            elif hash_algorithm == "sha256":
                return hashlib.sha256(data).hexdigest()
            elif hash_algorithm == "sha512":
                return hashlib.sha512(data).hexdigest()
            else:
                return None
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def monitor_running_processes():
    try:
        while True:
            processes = [proc.info for proc in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent", "exe"])]
            for process in processes:
                try:
                    process_info = {
                        "pid": process['pid'],
                        "name": process['name'],
                        "module": "process_information",
                        "memory_usage": process['memory_info'].rss,
                        "cpu_usage": process['cpu_percent'],
                        "timestamp": datetime.now().isoformat()
                    }
                    if process["exe"]:
                        exe_path = process["exe"]
                        process_info["md5_hash"] = calculate_hash(exe_path, "md5")
                        process_info["sha256_hash"] = calculate_hash(exe_path, "sha256")
                        process_info["sha512_hash"] = calculate_hash(exe_path, "sha512")
                    print(process_info)

                    try:
                        if es:
                            es.index(index=index_name, body=process_info)
                            logger.info(f"Indexed process: {process_info}")
                    except Exception as e:
                        logger.error(f"Failed to index process: {e}")
                except Exception as e:
                    logger.error(f"Error processing process info: {e}")

            time.sleep(60)  # Adjust sleep time based on your monitoring frequency
    except Exception as e:
        logger.error(f"Error monitoring running processes: {e}")

def get_user_accounts():
    try:
        result = subprocess.run(['net', 'user'], stdout=subprocess.PIPE, text=True)
        lines = result.stdout.split('\n')
        user_accounts = lines[4:-2]
        for user_account in user_accounts:
            try:
                user_info = {
                    "module": "user_accounts",
                    "user_account": user_account.strip(),
                    "timestamp": datetime.now().isoformat()
                }
                print(user_info)
                try:
                    if es:
                        es.index(index=index_name, body=user_info)
                        logger.info(f"Indexed user account: {user_info}")
                except Exception as e:
                    logger.error(f"Failed to index user account: {e}")
            except Exception as e:
                logger.error(f"Error processing user account info: {e}")
    except Exception as e:
        logger.error(f"Error fetching user accounts: {e}")

def get_internal_ip():
    try:
        hostname = socket.gethostname()
        internal_ip = socket.gethostbyname(hostname)
        return internal_ip
    except Exception as e:
        logger.error(f"Error fetching internal IP: {e}")
        return None

def get_external_ip():
    try:
        external_ip = requests.get('https://api.ipify.org').text
        return external_ip
    except requests.RequestException as e:
        logger.error(f"Error fetching external IP: {e}")
        return None

def monitor_network():
    try:
        external_ips = set()
        while True:
            internal_ip = get_internal_ip()
            external_ip = get_external_ip()
            if internal_ip:
                logger.info(f'Internal IP: {internal_ip}')
            if external_ip:
                logger.info(f'External IP: {external_ip}')
                if external_ip not in external_ips:
                    logger.info(f'New external IP detected: {external_ip}')
                    external_ips.add(external_ip)

            try:
                result = subprocess.run(['netstat', '-e'], stdout=subprocess.PIPE)
                netstat_output = result.stdout.decode()
                logger.info(netstat_output)

                connections = psutil.net_connections()
                logger.info("Proto  Local Address          Foreign Address        State")
                for conn in connections:
                    laddr = "%s:%s" % (conn.laddr)
                    raddr = "%s:%s" % (conn.raddr) if conn.raddr else ""

                    proto = conn.type
                    if proto == socket.SOCK_STREAM:
                        proto_name = 'TCP'
                    elif proto == socket.SOCK_DGRAM:
                        proto_name = 'UDP'
                    else:
                        proto_name = 'OTHER'

                    connection_info = {
                        "protocol": proto_name,
                        "module": "network_monitor",
                        "local_address": laddr,
                        "remote_address": raddr,
                        "state": conn.status,
                        "timestamp": datetime.now().isoformat()
                    }
                    logger.info(f"{proto_name}    {laddr}    {raddr}    {conn.status}")

                    try:
                        if es:
                            es.index(index=index_name, body=connection_info)
                            logger.info(f"Indexed connection info: {connection_info}")
                    except Exception as e:
                        logger.error(f"Failed to index connection info: {e}")

            except Exception as e:
                logger.error(f"Error monitoring network: {e}")

            time.sleep(60)  # Adjust sleep time based on your monitoring frequency
    except Exception as e:
        logger.error(f"Error in network monitoring thread: {e}")

def get_drives():
    try:
        drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if win32file.GetDriveType(f"{d}:\\") == win32con.DRIVE_REMOVABLE]
        return drives
    except Exception as e:
        logger.error(f"Error fetching drives: {e}")
        return []

def monitor_drives():
    try:
        old_drives = get_drives()
        while True:
            try:
                new_drives = get_drives()
                added = [d for d in new_drives if d not in old_drives]
                removed = [d for d in old_drives if d not in new_drives]
                if added:
                    print(f"New drive(s) added: {', '.join(added)}")
                if removed:
                    print(f"Drive(s) removed: {', '.join(removed)}")
                old_drives = new_drives

                event = {
                    'timestamp': datetime.now().isoformat(),
                    "module": "driver_monitoring",
                    'added_drives': added,
                    'removed_drives': removed,
                }

                try:
                    if es:
                        es.index(index=index_name, body=event)
                        logger.info(f"Indexed drive event: {event}")
                except Exception as e:
                    logger.error(f"Failed to index drive event: {e}")

            except Exception as e:
                logger.error(f"Error processing drive monitoring: {e}")

            time.sleep(60)  # Adjust sleep time based on your monitoring frequency
    except Exception as e:
        logger.error(f"Error in drive monitoring thread: {e}")

def get_sha256(file_path):
    try:
        """Compute the SHA-256 hash of the given file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error calculating SHA-256 hash for {file_path}: {e}")
        return None

def terminate_process_by_hash(target_hash):
    try:
        """Terminate a process by its executable file's SHA-256 hash."""
        for proc in psutil.process_iter(['pid', 'exe', 'name']):
            try:
                exe_path = proc.info['exe']
                if exe_path and os.path.exists(exe_path):
                    process_hash = get_sha256(exe_path)
                    if process_hash == target_hash:
                        print(f"Terminating process {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.terminate()
                        proc.wait()  # Wait for the process to terminate
                        print(f"Process {proc.info['name']} (PID: {proc.info['pid']}) terminated.")
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logger.error(f"Error terminating process: {e}")
                pass
        print(f"No process found with SHA-256 hash: {target_hash}")
        return False
    except Exception as e:
        logger.error(f"Error terminating process: {e}")
        return False
@app.route('/terminate', methods=['POST'])
def terminate_process_api():
    data = request.get_json(force=True)
    target_hash = data.get('hash')
    if not target_hash:
        return jsonify({"error": "Hash is required"}), 400

    # Validate hash format (e.g., SHA-256 should be 64 hex characters)
    if not re.match(r'^[a-fA-F0-9]{64}$', target_hash):
        return jsonify({"error": "Invalid hash format"}), 400

    success = terminate_process_by_hash(target_hash)
    if success:
        return jsonify({"message": "Process terminated successfully."}), 200
    else:
        return jsonify({"message": "Process not found."}), 404
def run_flask_app():
    try:
        # Use Waitress as the WSGI server with multithreading enabled
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000, threads=100)
    except Exception as e:
        logger.error(f"Error running Flask app: {e}")

def monitor_system_resources():
    """
    Monitor system resources (CPU, memory, and disk usage) and log warnings if thresholds are exceeded.
    """
    while True:
        # Measure total system usage
        cpu_usage = psutil.cpu_percent(interval=1)  # Measure over 1 second
        memory_info = psutil.virtual_memory()
        disk_usage = psutil.disk_usage('/')

        # Check if overall system usage exceeds thresholds
        if cpu_usage > 90:
            logger.warning(f"High total CPU usage detected: {cpu_usage}%")
        if memory_info.percent > 95:
            logger.warning(f"High total memory usage detected: {memory_info.percent}%")
        if disk_usage.percent > 90:
            logger.warning(f"High total disk usage detected: {disk_usage.percent}%")

        # Iterate over all processes
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # Fetch process details
                process_info = proc.info
                pid = process_info['pid']
                name = process_info['name']
                cpu_percent = process_info['cpu_percent']
                memory_percent = process_info['memory_percent']

                # Check if the process exceeds CPU and memory usage thresholds
                if cpu_percent > 10:  # Example threshold for individual process CPU usage
                    logger.warning(f"High CPU usage detected for process: {name} (PID: {pid}) - {cpu_percent}%")
                if memory_percent > 10:  # Example threshold for individual process memory usage
                    logger.warning(f"High memory usage detected for process: {name} (PID: {pid}) - {memory_percent}%")

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error(f"Error accessing process information: {e}")
        time.sleep(5)

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

def detect_data_exfiltration():
    """
    Monitor network interfaces for potential data exfiltration by tracking sent data.
    """
    # Example threshold for data transfer in bytes (1 MB)
    data_transfer_threshold = 10000000
    
    # Store the previous state of bytes sent per interface
    previous_stats = {iface: stats.bytes_sent for iface, stats in psutil.net_io_counters(pernic=True).items()}

    logger.info("Monitoring for potential data exfiltration...")

    try:
        while True:
            # Get current network I/O counters
            current_stats = psutil.net_io_counters(pernic=True)

            for iface, stats in current_stats.items():
                # Calculate the bytes sent since the last check
                bytes_sent_since_last_check = stats.bytes_sent - previous_stats.get(iface, 0)

                if bytes_sent_since_last_check > data_transfer_threshold:
                    logger.warning(f"Potential data exfiltration detected on interface {iface}: {bytes_sent_since_last_check} bytes sent")

                # Update the stored previous bytes sent for the interface
                previous_stats[iface] = stats.bytes_sent

            # Sleep for a specified interval before the next check
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Exfiltration monitoring stopped by user.")

def disable_network_interfaces_windows():
    """
    Disable all network interfaces except loopback on a Windows machine.
    """
    try:
        # Get all network interfaces
        interfaces = psutil.net_if_addrs()

        for iface in interfaces:
            # Skip loopback interface
            if iface.startswith('Loopback') or iface == 'lo':
                continue

            logger.info(f"Disabling interface: {iface}")

            # Use netsh to disable the interface
            result = subprocess.run(['netsh', 'interface', 'set', 'interface', iface, 'admin=DISABLED'], 
                                    capture_output=True, text=True, check=False)

            if result.returncode == 0:
                logger.info(f"Interface {iface} disabled successfully.")
            else:
                logger.error(f"Failed to disable interface {iface}. Error: {result.stderr.strip()}")

    except Exception as e:
        logger.error(f"An error occurred while disabling network interfaces: {e}")

@app.route('/isolate', methods=['POST'])
def isolate_machine():
    """
    Endpoint to isolate the machine by disabling network interfaces.
    """
    logger.info("Starting machine isolation process via API...")
    disable_network_interfaces_windows()
    return jsonify({"message": "Machine isolation process initiated."}), 200

if __name__ == "__main__":
    try:
        directories_to_watch = [
            r'C:/'
        ]

        # Start monitoring threads
        threads = []
        for directory in directories_to_watch:
            watch_thread = threading.Thread(target=watch_directory, args=(directory,))
            threads.append(watch_thread)
            watch_thread.start()

        open_ports_thread = threading.Thread(target=monitor_open_ports)
        threads.append(open_ports_thread)
        open_ports_thread.start()

        processes_thread = threading.Thread(target=monitor_running_processes)
        threads.append(processes_thread)
        processes_thread.start()

        user_accounts_thread = threading.Thread(target=get_user_accounts)
        threads.append(user_accounts_thread)
        user_accounts_thread.start()

        network_thread = threading.Thread(target=monitor_network)
        threads.append(network_thread)
        network_thread.start()

        drives_thread = threading.Thread(target=monitor_drives)
        threads.append(drives_thread)
        drives_thread.start()

        resources_thread = threading.Thread(target=monitor_system_resources)
        threads.append(resources_thread)
        resources_thread.start()

        exfiltration_thread = threading.Thread(target=detect_data_exfiltration)
        threads.append(exfiltration_thread)
        exfiltration_thread.start()
        
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)  # Ensure Flask runs in the main thread
        
        # Start Flask app in a separate thread
        flask_thread = threading.Thread(target=run_flask_app)
        threads.append(flask_thread)
        flask_thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()
    except Exception as e:
        logger.error(f"Main thread error: {e}")
