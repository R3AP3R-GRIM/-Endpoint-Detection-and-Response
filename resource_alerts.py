import psutil
import logging
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

        # Sleep for 5 seconds before the next check
        time.sleep(5)

if __name__ == "__main__":
    monitor_system_resources()
