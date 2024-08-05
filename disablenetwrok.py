import psutil
import subprocess
import logging
from flask import Flask, jsonify

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

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
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
