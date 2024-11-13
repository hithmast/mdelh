import json
import aiohttp
import asyncio
import time
import logging
import re
import signal
import sys
import os
import csv
import ipaddress
import aiofiles
from dateutil.parser import parse
import pytz
import argparse
from typing import Optional

API_URL = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

# Rate limits
MAX_CALLS_PER_MINUTE = 45
MAX_CALLS_PER_HOUR = 1500

# Global variables for rate limiting
calls_made = 0
start_time_minute = time.time()
start_time_hour = time.time()

# Counters for each query type
query_counts = {
    "SHA256": 0,
    "SHA1": 0,
    "MD5": 0,
    "RemoteIP": 0,
    "RemoteUrl": 0,
    "LocalIP": 0
}
# Custom exceptions for different error
class APIUnauthorizedError(Exception):
    """Exception raised for unauthorized access (401)."""
    pass

class APIForbiddenError(Exception):
    """Exception raised for forbidden access (403)."""
    pass

class APINotFoundError(Exception):
    """Exception raised when a resource is not found (404)."""
    pass

class APIServerError(Exception):
    """Exception raised for server errors (5xx)."""
    pass

class APIError(Exception):
    """General exception for other API errors."""
    pass

# Timezone conversion
def convert_to_cairo_time(timestamp_str: str) -> str:
    """Convert a UTC timestamp string to Cairo time.

    Args:
        timestamp_str (str): The UTC timestamp string.

    Returns:
        str: The converted timestamp in Cairo time.
    """
    try:
        utc_dt = parse(timestamp_str)
        cairo_tz = pytz.timezone('Africa/Cairo')
        cairo_dt = utc_dt.astimezone(cairo_tz)
        return cairo_dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        logging.error("Error converting timestamp: %s, Error: %s", timestamp_str, e)
        return ""

# Validation functions
def is_sha256(value: str) -> bool:
    """Check if a string is a valid SHA256 hash.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid SHA256, False otherwise.
    """
    return len(value) == 64 and set(value.lower()).issubset("0123456789abcdef")

def is_sha1(value: str) -> bool:
    """Check if a string is a valid SHA1 hash.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid SHA1, False otherwise.
    """
    return len(value) == 40 and set(value.lower()).issubset("0123456789abcdef")

def is_md5(value: str) -> bool:
    """Check if a string is a valid MD5 hash.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid MD5, False otherwise.
    """
    return len(value) == 32 and set(value.lower()).issubset("0123456789abcdef")

def is_ipv4(value: str) -> bool:
    """Check if a string is a valid public IPv4 address.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid public IPv4, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(value)
        return isinstance(ip, ipaddress.IPv4Address) and not ip.is_private
    except ValueError:
        return False

def is_private_ipv4(value: str) -> bool:
    """Check if a string is a valid private IPv4 address.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid private IPv4, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(value)
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_private
    except ValueError:
        return False

def is_url(value: str) -> bool:
    """Check if a string is a valid URL.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid URL, False otherwise.
    """
    return bool(re.match(
        r'^(https?|ftp):\/\/'  # Scheme (http, https, ftp)
        r'('
        r'([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'  # Domain name
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP address
        r'\[?[a-fA-F0-9:]+\]?'  # IPv6 address
        r')'
        r'(:\d+)?'  # Optional port
        r'(\/[^?#\s]*)?'  # Optional path
        r'(\?[^#\s]*)?'  # Optional query string
        r'(#\S*)?$',  # Optional fragment
        value
    ))

def is_hostname(value: str) -> bool:
    """Check if a string is a valid hostname.

    Args:
        value (str): The string to check.

    Returns:
        bool: True if valid hostname, False otherwise.
    """
    if len(value) > 255:
        return False
    if value[-1] == ".":
        value = value[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in value.split("."))

async def load_config(config_file: str):
    """Load configuration from a JSON file asynchronously."""
    if not os.path.isfile(config_file):
        logging.error(f"Configuration file '{config_file}' does not exist.")
        raise FileNotFoundError(f"Configuration file '{config_file}' not found.")
    
    async with aiofiles.open(config_file, 'r') as file:
        return json.loads(await file.read())
        
async def fetch_device_software_inventory(api_token, device_inv):
    # Define the KQL query
    kql_query = f"""
    DeviceTvmSoftwareInventory
    | project DeviceId, DeviceName, SoftwareName, SoftwareVersion, OSPlatform, OSVersion
    | where SoftwareName !in ("android", "Linux", "Android") and DeviceName has "." and DeviceName contains "{device_inv}"
    | order by DeviceName asc
    """

    # Prepare the request payload
    payload = {
        "query": kql_query
    }

    # Set up the headers
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(API_URL, headers=headers, json=payload) as response:
            if response.status == 200:
                data = await response.json()
                return data
            elif response.status == 401:
                print("The API token is invalid or expired. Please check your credentials.")
                # Stop further execution
                raise SystemExit("Exiting due to unauthorized access.")
            elif response.status == 403:
                error_message = await response.text()
                print(f"Error: 403 Forbidden - {error_message}")
                return None
            elif response.status == 404:
                error_message = await response.text()
                print(f"Error: 404 Not Found - {error_message}")
                return None
            elif response.status >= 500:
                error_message = await response.text()
                print(f"Error: {response.status} - Server error - {error_message}")
                return None
            else:
                error_message = await response.text()
                print(f"Error: {response.status} - {error_message}")
                return None

async def query_device_inventory(api_token, device_names_file):
    """Query device software inventory based on device names from the specified file."""
    if not os.path.isfile(device_names_file):
        logging.error(f"Device names file '{device_names_file}' does not exist.")
        return

    async with aiofiles.open(device_names_file, 'r') as file:
        device_names = [line.strip() for line in await file.readlines()]

    for device_name in device_names:
        if device_name:  # Ensure the device name is not empty
            try:
                result = await fetch_device_software_inventory(api_token, device_name)
                if result:
                    print(json.dumps(result, indent=4))
            except APIUnauthorizedError as e:
                print(e)
                raise SystemExit("Exiting due to unauthorized access.")
            except APIForbiddenError as e:
                print(e)
            except APINotFoundError as e:
                print(e)
            except APIServerError as e:
                print(e)
            except APIError as e:
                print(e)
                
# Query MDE
async def query_mde(session: aiohttp.ClientSession, api_token: str, query: str, retries: int = 10, backoff_factor: int = 5) -> Optional[dict]:
    """Query the Microsoft Defender API for a specific query.

    Args:
        session (aiohttp.ClientSession): The aiohttp session to use for the request.
        api_token (str): The API token for authentication.
        query (str): The query string to send.
        retries (int): The number of retries on failure.
        backoff_factor (int): The backoff factor for retries.

    Returns:
        dict: The JSON response from the API.
    """
    global calls_made, start_time_minute, start_time_hour

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    query_data = {"Query": query}
    current_time = time.time()

    # Rate limit checks
    if calls_made >= MAX_CALLS_PER_MINUTE:
        elapsed_time_minute = current_time - start_time_minute
        if elapsed_time_minute < 60:
            await asyncio.sleep(60 - elapsed_time_minute)
        start_time_minute = time.time()
        calls_made = 0

    if calls_made >= MAX_CALLS_PER_HOUR:
        elapsed_time_hour = current_time - start_time_hour
        if elapsed_time_hour < 3600:
            await asyncio.sleep(3600 - elapsed_time_hour)
        start_time_hour = time.time()
        calls_made = 0

    for attempt in range(retries):
        try:
            async with session.post(API_URL, headers=headers, json=query_data) as response:
                if response.status == 401:
                    logging.error("API Key is deprecated. Please update the config.json file.")
                    sys.exit(1)
                response.raise_for_status()  # Raises an error for bad responses
                calls_made += 1
                return await response.json()
        except aiohttp.ClientError as e:
            logging.error("Error querying MDE: %s", e)

            # Handle specific exceptions
            if isinstance(e, aiohttp.ClientConnectionError):
                logging.error("Connection error occurred. Retrying...")
            elif isinstance(e, aiohttp.ClientTimeout):
                logging.error("Request timed out. Retrying...")
            elif hasattr(e, 'status') and e.status == 429:
                wait_time = backoff_factor * (attempt + 1)
                logging.error("Rate limit exceeded. Retrying in %d seconds...", wait_time)
                await asyncio.sleep(wait_time)
                continue  # Retry on 429
            elif hasattr(e, 'status') and e.status == 502:
                logging.error("Bad Gateway error occurred. This may be a temporary issue. Retrying...")
                wait_time = backoff_factor * (attempt + 1)
                await asyncio.sleep(wait_time)
                continue  # Retry on 502
            else:
                # Catch-all for other ClientErrors
                logging.error("An unexpected error occurred: %s. Continuing to the next query...", e)
                return None  # Return None to allow continuing

        except Exception as e:
            logging.error("An unexpected error occurred: %s. Continuing to the next query...", e)
            return None  # Return None to allow continuing
    return None

# Process items
async def process_items(items: list, api_token: str):
    """Process a list of items and query the Microsoft Defender API.

    Args:
        items (list): The list of items to process.
        api_token (str): The API token for authentication.
    """
    query_count = 0
    critical_error_occurred = False

    query_mapping = {
        "SHA256": lambda item: f"""
            DeviceFileEvents
            | where SHA256 == '{item}'
            | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, FileSize, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine
            | limit 1000
        """,
        "SHA1": lambda item: f"""
            DeviceFileEvents
            | where SHA1 == '{item}'
            | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, FileSize, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine
            | limit 1000
        """,
        "MD5": lambda item: f"""
            DeviceFileEvents
            | where MD5 == '{item}'
            | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, FileSize, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine
            | limit 1000
        """,
        "RemoteIP": lambda item: f"""
            DeviceNetworkEvents
            | where RemoteIP == '{item}'
            | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol
            | limit 1000
        """,
        "RemoteUrl": lambda item: f"""
            DeviceNetworkEvents
            | where RemoteUrl contains '{item}'
            | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol
            | limit 1000
        """,
        "LocalIP": lambda item: f"""
            DeviceNetworkEvents
            | where LocalIP == '{item}'
            | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol
            | limit 1000
        """
    }

    results_folder = "results"
    os.makedirs(results_folder, exist_ok=True)
    csv_file_path = os.path.join(results_folder, "results.csv")

    def get_query(item: str) -> str:
        """Get the appropriate query for the given item.

        Args:
            item (str): The item to query.

        Returns:
            str: The query string or None if invalid.
        """
        if not item:  # Check if the item is an empty string
            logging.warning("Received an empty item. Skipping...")
            return ""
        if is_sha256(item):
            query_counts["SHA256"] += 1
            return query_mapping["SHA256"](item)
        elif is_sha1(item):
            query_counts["SHA1"] += 1
            return query_mapping["SHA1"](item)
        elif is_md5(item):
            query_counts["MD5"] += 1
            return query_mapping["MD5"](item)
        elif is_ipv4(item):
            query_counts["RemoteIP"] += 1
            return query_mapping["RemoteIP"](item)
        elif is_private_ipv4(item):
            query_counts["LocalIP"] += 1
            return query_mapping["LocalIP"](item)
        elif is_url(item) or is_hostname(item):
            query_counts["RemoteUrl"] += 1
            return query_mapping["RemoteUrl"](item)
        else:
            logging.warning("Invalid item format: %s", item)
            return ""

    async def process_item(session: aiohttp.ClientSession, item: str):
        """Process a single item and query the API.

        Args:
            session (aiohttp.ClientSession): The aiohttp session to use for the request.
            item (str): The item to process.
        """
        nonlocal query_count, critical_error_occurred
        if critical_error_occurred:
            return
        
        query = get_query(item)
        if not query:
            return
        
        query_count += 1
        result = await query_mde(session, api_token, query)
        if result is None:
            logging.error("Failed to get result for query: %s. Stopping further processing.", query)
            critical_error_occurred = True
            return

        if "Results" in result and result["Results"]:
            async with aiofiles.open(csv_file_path, 'a', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    "Timestamp", "DeviceName", "DeviceId", "RemoteIP", "RemoteUrl",
                    "FileName", "FolderPath", "FileSize", "SHA256", "SHA1", "FileType", "LocalIP"
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                # Write header if the file is empty
                if csvfile.tell() == 0:
                    writer.writeheader()  # Remove await

                for res_item in result["Results"]:
                    output_data = {
                        "Timestamp": convert_to_cairo_time(res_item.get("Timestamp", "")),
                        "DeviceName": res_item.get("DeviceName", ""),
                        "DeviceId": res_item.get("DeviceId", ""),
                        "RemoteIP": res_item.get("RemoteIP", ""),
                        "RemoteUrl": res_item.get("RemoteUrl", ""),
                        "FileName": res_item.get("FileName", ""),
                        "FolderPath": res_item.get("FolderPath", ""),
                        "FileSize": res_item.get("FileSize", ""),
                        "SHA256": res_item.get("SHA256", ""),
                        "SHA1": res_item.get("SHA1", ""),
                        "FileType": res_item.get("FileType", ""),
                        "LocalIP": res_item.get("LocalIP", "")
                    }
                    writer.writerow(output_data)  # Remove await
        else:
            logging.info("No results found for query: %s", query)

    start_time = time.time()

    async with aiohttp.ClientSession() as session:
        for item in items:
            await process_item(session, item)

    # Log the number of queries for each type
    for query_type, count in query_counts.items():
        logging.info("Total queries for %s: %d", query_type, count)

    total_time = time.time() - start_time
    logging.info("Total execution time: %.2f seconds", total_time)
    logging.info("Total queries processed: %d", query_count)

def handle_interrupt(signum, frame):
    """Handle script interruption.

    Args:
        signum: The signal number.
        frame: The current stack frame.
    """
    logging.info("Script interrupted by user. Exiting...")
    sys.exit()
    
async def process_iocs(iocs_file: str, api_token: str):
    """Process Indicators of Compromise (IOCs) from the specified file."""
    if not os.path.isfile(iocs_file):
        logging.error("Invalid IOC file provided. Please check the file path and try again.")
        return

    # Read items from IOC file
    try:
        with open(iocs_file, 'r') as file:
            hashes = [line.strip() for line in file]
    except Exception as e:
        logging.error("Error reading IOC file '%s': %s", iocs_file, e)
        return

    try:
        await process_items(hashes, api_token)  # Assuming process_items is defined elsewhere
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        
async def main(iocs_file: str = None, device_names_file: str = None):
    """Main function to load configuration and execute the specified operation."""
    config = await load_config('config.json')  # Load config asynchronously
    api_token = config.get("api_token")

    # Register the signal handler for SIGINT
    signal.signal(signal.SIGINT, handle_interrupt)

    if iocs_file:
        await process_iocs(iocs_file, api_token)
    elif device_names_file:
        await query_device_inventory(api_token, device_names_file)
    else:
        logging.error("No valid operation specified. Please use --iocs or --di.")

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Process Indicators of Compromise (IOCs) or query Device Software Inventory using the Microsoft Defender API.",
        epilog="Example usage:\n  python your_script.py --iocs path/to/iocs.txt\n  python your_script.py --di path/to/device_names.txt"
    )
    parser.add_argument(
        '--iocs',
        type=str,
        help='Path to the file containing IOCs (one per line).'
    )
    parser.add_argument(
        '--di',
        type=str,
        help='Path to the file containing device names (one per line).'
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    asyncio.run(main(args.iocs, args.di))
