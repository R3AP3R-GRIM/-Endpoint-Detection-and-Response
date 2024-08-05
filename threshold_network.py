import psutil
import logging
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def detect_data_exfiltration():
    """
    Monitor network interfaces for potential data exfiltration by tracking sent data.
    """
    # Example threshold for data transfer in bytes ~ (1 GB)
    data_transfer_threshold = 1000000000
    
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
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Exfiltration monitoring stopped by user.")

if __name__ == "__main__":
    detect_data_exfiltration()
