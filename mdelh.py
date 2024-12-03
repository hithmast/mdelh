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
from typing import Optional, List

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

# Global variable to track if an interrupt has occurred
interrupt_occurred = False

# Custom exceptions for different error scenarios
class APIUnauthorizedError(Exception):
    pass

class APIForbiddenError(Exception):
  """Raised when the API returns a 403 Forbidden response."""
  pass

class APINotFoundError(Exception):
  """Raised when the API returns a 404 Not Found response."""
  pass

class APIServerError(Exception):
  """Raised when the API returns a server error response (status code >= 500)."""
  pass

class APIError(Exception):
  """Raised for any other unexpected API error."""
  pass

# Timezone conversion
def convert_to_cairo_time(timestamp_str: str) -> str:
  """Converts a UTC timestamp string to Cairo time (Africa/Cairo timezone).

  Args:
      timestamp_str: The UTC timestamp string in ISO 8601 format.

  Returns:
      The converted timestamp string in the format "%Y-%m-%d %H:%M:%S", or an empty string if the conversion fails.
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
  """Checks if the provided value is a valid SHA256 hash.

  Args:
      value: The string to validate.

  Returns:
      True if the value is a valid SHA256 hash (length 64 and characters are lowercase a-f and 0-9), False otherwise.
  """
  return len(value) == 64 and set(value.lower()).issubset("0123456789abcdef")

def is_sha1(value: str) -> bool:
    """Checks if the provided value is a valid SHA1 hash.

  Args:
      value: The string to validate.

  Returns:
      True if the value is a valid SHA1 hash (length 40 and characters are lowercase a-f and 0-9), False otherwise.
  """
    return len(value) == 40 and set(value.lower()).issubset("0123456789abcdef")

def is_md5(value: str) -> bool:
    """Checks if the provided value is a valid MD5 hash.

  Args:
      value: The string to validate.

  Returns:
      True if the value is a valid MD5 hash (length 32 and characters are lowercase a-f and 0-9), False otherwise.
  """
    return len(value) == 32 and set(value.lower()).issubset("0123456789abcdef")

def is_ipv4(value: str) -> bool:
  """Checks if the provided value is a valid non-private IPv4 address.

  Args:
      value: The string to validate.

  Returns:
      True if the value is a valid non-private IPv4 address, False otherwise.
  """
  try:
    ip = ipaddress.ip_address(value)
    return isinstance(ip, ipaddress.IPv4Address) and not ip.is_private
  except ValueError:
    return False

def is_private_ipv4(value: str) -> bool:
    """Checks if the provided value is a valid private IPv4 address.

  Args:
      value: The string to validate.

  Returns:
      True if the value is a valid private IPv4 address, False otherwise.
  """
    try:
        ip = ipaddress.ip_address(value)
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_private
    except ValueError:
        return False

def is_url(value: str) -> bool:
      """Checks if the provided value is a valid URL.

  Args:
      value: The string to validate.

  Returns:
      True if the value is a valid URL, False otherwise.
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
    """Checks if the provided value is a valid hostname."""
    if len(value) > 255:
        return False
    if value[-1] == ".":
        value = value[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in value.split("."))

async def load_config(config_file: str):
      """Loads the configuration from the specified JSON file.

  Args:
      config_file: The path to the configuration file.

  Raises:
      FileNotFoundError: If the configuration file does not exist.

  Returns:
      The parsed configuration as a dictionary.
  """
      if not os.path.isfile(config_file):
        logging.error("Configuration file '%s' does not exist.", config_file)
        raise FileNotFoundError("Configuration file '%s' not found." % config_file)
      async with aiofiles.open(config_file, 'r') as file:
          return json.loads(await file.read())

async def execute_query(api_token, payload):
      """Executes a query to the Microsoft Security Center API.

  Args:
      api_token: The API token for authentication.
      payload: The query payload as a JSON object.

  Raises:
      APIUnauthorizedError: If the API token is invalid or expired.
      APIForbiddenError: If the API returns a 403 Forbidden response.
      APINotFoundError: If the API returns a 404 Not Found response.
      APIServerError: If the API returns a server error response (status code >= 500).
      APIError: For any other unexpected API error.

  Returns:
      The JSON response from the API, or None if an error occurs.
  """
      headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"}
      async with aiohttp.ClientSession() as session:
          async with session.post(API_URL, headers=headers, json=payload) as response:
              if response.status == 200:
                return await response.json()
              elif response.status == 401:
                    raise APIUnauthorizedError("The API token is invalid or expired. Please check your credentials.")
              elif response.status == 403:
                    error_message = await response.text()
                    raise APIForbiddenError("403 Forbidden - %s" % error_message)
              elif response.status == 404:
                    error_message = await response.text()
                    raise APINotFoundError("404 Not Found - %s" % error_message)
              elif response.status >= 500:
                    error_message = await response.text()
                    raise APIServerError("500 - Server error - %s" % error_message)
              else:
                    error_message = await response.text()
                    raise APIError("%s - %s" % (response.status, error_message))

async def fetch_device_software_inventory(api_token, device_inv):
    # Construct the KQL query
    kql_query = f"""
    DeviceTvmSoftwareInventory
    | where DeviceName contains "{device_inv}"
    | project DeviceId, DeviceName, SoftwareName, SoftwareVersion, OSPlatform, OSVersion
    | order by DeviceName asc
    | limit 1000
    """
    
    # Ensure the payload is correctly structured
    payload = {
        "Query": kql_query  # Ensure the query is included in the payload
    }
    
    return await execute_query(api_token, payload)  # Pass the payload to execute_query

async def query_device_inventory(api_token, device_names_file):
    logging.info("Starting query_device_inventory with file: %s", device_names_file)  # Log start of function
    if not os.path.isfile(device_names_file):
        logging.error(f"Device names file '{device_names_file}' does not exist.")
        return

    async with aiofiles.open(device_names_file, 'r') as file:
        device_names = [line.strip() for line in await file.readlines()]
    logging.info("Loaded %d device names from file.", len(device_names))  # Log number of device names loaded

    # New CSV file for device inventory results
    inventory_results_file = "results/device_inventory_results.csv"
    fieldnames = [
        "DeviceId", "DeviceName", "SoftwareName", "SoftwareVersion", "OSPlatform", "OSVersion"
    ]

    # Retry logic for opening the CSV file
    for _ in range(5):  # Retry up to 5 times
        if interrupt_occurred:
            logging.info("Exiting due to user interrupt during file opening.")
            return
        try:
            async with aiofiles.open(inventory_results_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                await writer.writeheader()  # Write the header row
            break  # Exit the loop if successful
        except PermissionError:
            logging.warning("Permission denied for file '%s'. Retrying in 1 second...", inventory_results_file)
            await asyncio.sleep(1)  # Wait before retrying
    else:
        logging.error(f"Failed to open file '{inventory_results_file}' after multiple attempts.")
        return  # Exit if unable to open the file

    for device_name in device_names:
        if interrupt_occurred:
            logging.info("Exiting due to user interrupt during device processing.")
            return

        if device_name:
            logging.info("Processing device: %s", device_name)  # Log each device being processed
            try:
                # Call the fetch function to get the inventory
                result = await fetch_device_software_inventory(api_token, device_name)
                if result:
                    # Write each result to the CSV file
                    for item in result.get("Results", []):
                        if interrupt_occurred:
                            logging.info("Exiting due to user interrupt during result processing.")
                            return

                        output_data = {
                            "DeviceId": item.get("DeviceId", ""),
                            "DeviceName": item.get("DeviceName", ""),
                            "SoftwareName": item.get("SoftwareName", ""),
                            "SoftwareVersion": item.get("SoftwareVersion", ""),
                            "OSPlatform": item.get("OSPlatform", ""),
                            "OSVersion": item.get("OSVersion", "")
                        }
                        async with aiofiles.open(inventory_results_file, 'a', newline='', encoding='utf-8') as csvfile:
                            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                            await writer.writerow(output_data)  # Write each result immediately
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

async def query_mde(session: aiohttp.ClientSession, api_token: str, query: str, retries: int = 10, backoff_factor: int = 5) -> Optional[dict]:
    global calls_made, start_time_minute, start_time_hour

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    query_data = {"Query": query}
    current_time = time.time()

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
                response.raise_for_status()
                calls_made += 1
                return await response.json()
        except aiohttp.ClientError as e:
            logging.error("Error querying MDE: %s", e)
            if isinstance(e, aiohttp.ClientConnectionError):
                logging.error("Connection error occurred. Retrying...")
            elif isinstance(e, aiohttp.ClientTimeout):
                logging.error("Request timed out. Retrying...")
            elif hasattr(e, 'status') and e.status == 429:
                wait_time = backoff_factor * (attempt + 1)
                logging.error("Rate limit exceeded. Retrying in %d seconds...", wait_time)
                await asyncio.sleep(wait_time)
                continue
            elif hasattr(e, 'status') and e.status == 502:
                logging.error("Bad Gateway error occurred. This may be a temporary issue. Retrying...")
                wait_time = backoff_factor * (attempt + 1)
                await asyncio.sleep(wait_time)
                continue
            else:
                logging.error("An unexpected error occurred: %s. Continuing to the next query...", e)
                return None

        except Exception as e:
            logging.error("An unexpected error occurred: %s. Continuing to the next query...", e)
            return None
    return None

async def process_items(items: list, api_token: str):
    start_time = time.time()
    query_count = 0
    critical_error_occurred = False

    results_folder = "results"
    os.makedirs(results_folder, exist_ok=True)
    csv_file_path = os.path.join(results_folder, "results.csv")

    # Initialize CSV file with headers
    fieldnames = [
        "Timestamp", "DeviceName", "DeviceId", "RemoteIP", "RemoteUrl",
        "FileName", "FolderPath", "FileSize", "SHA256", "SHA1", "FileType", 
        "LocalIP", "InitiatingProcessFileName", "InitiatingProcessCommandLine"
    ]
    
    async with aiofiles.open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        await writer.writeheader()

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

    def get_query(item: str) -> str:
        if not item:
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
        nonlocal query_count, critical_error_occurred
        if critical_error_occurred or interrupt_occurred:
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

        # Check for interrupt before processing results
        if interrupt_occurred:
            user_input = input("An error occurred. Do you want to continue processing? (y/n): ")
            if user_input.lower() != 'y':
                logging.info("Exiting as per user request.")
                sys.exit()

        # Process results
        if "Results" in result and result["Results"]:
            async with aiofiles.open(csv_file_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                for res_item in result["Results"]:
                    if interrupt_occurred:
                        return

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
                        "LocalIP": res_item.get("LocalIP", ""),
                        "InitiatingProcessFileName": res_item.get("InitiatingProcessFileName", ""),
                        "InitiatingProcessCommandLine": res_item.get("InitiatingProcessCommandLine", "")
                    }
                    await writer.writerow(output_data)
        else:
            logging.info("No results found for query: %s", query)

    async with aiohttp.ClientSession() as session:
        for item in items:
            if interrupt_occurred:
                logging.info("Exiting due to user interrupt during item processing.")
                break
            await process_item(session, item)

        for query_type, count in query_counts.items():
            logging.info("Total queries for %s: %d", query_type, count)

        total_time = time.time() - start_time
        logging.info("Total execution time: %.2f seconds", total_time)
        logging.info("Total queries processed: %d", query_count)

        if query_count > 0 and critical_error_occurred:
            logging.error("Critical error occurred during processing.")

def handle_interrupt(signum, frame):
    global interrupt_occurred
    interrupt_occurred = True  # Set the flag when interrupted
    logging.info("Script interrupted by user. Exiting...")

async def process_iocs(iocs_file: str, api_token: str):
    if not os.path.isfile(iocs_file):
        logging.error("Invalid IOC file provided. Please check the file path and try again.")
        return

    try:
        with open(iocs_file, 'r') as file:
            hashes = [line.strip() for line in file]
    except Exception as e:
        logging.error("Error reading IOC file '%s': %s", iocs_file, e)
        return

    try:
        await process_items(hashes, api_token)
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")

async def query_email_inventory(api_token, emails_file: str):
    """Queries the Microsoft Security Center API for device events based on email addresses.

    Args:
        api_token: The API token for authentication.
        emails_file: The path to the file containing email addresses (one per line).

    Returns:
        None
    """
    if not os.path.isfile(emails_file):
        logging.error("Invalid email file provided. Please check the file path and try again.")
        return

    try:
        async with aiofiles.open(emails_file, 'r') as file:
            emails = [line.strip() for line in await file.readlines()]
    except Exception as e:
        logging.error("Error reading email file '%s': %s", emails_file, e)
        return

    for email in emails:
        logging.info("Querying for email: %s", email)  # Log each email being processed
        kql_query = f"""
        DeviceEvents 
        | where InitiatingProcessAccountUpn == "{email}"
        | distinct DeviceId, DeviceName
        """
        
        payload = {
            "Query": kql_query  # Ensure the query is included in the payload
        }
        
        result = await execute_query(api_token, payload)  # Execute the query
        if result:
            logging.info("Results for %s: %s", email, result.get("Results", []))
        else:
            logging.info("No results found for email: %s", email)

# Add this after the imports
BANNER = r"""
███╗   ███╗██████╗ ███████╗██╗     ██╗  ██╗
████╗ ████║██╔══██╗██╔════╝██║     ██║  ██║
██╔████╔██║██║  ██║█████╗  ██║     ███████║
██║╚██╔╝██║██║  ██║██╔══╝  ██║     ██╔══██║
██║ ╚═╝ ██║██████╔╝███████╗███████╗██║  ██║
╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
------------------------------                                           
Microsoft Defender Lazy Hunter
Author: Aly Emara
Version: 1.0.0
------------------------------
"""

def check_python_version():
    """Check if Python version is 3.7 or higher."""
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        sys.exit(1)

def check_config_exists():
    """Check if config.json exists."""
    if not os.path.exists('config.json'):
        print("Error: config.json not found")
        print("Please create a config.json file with your API token:")
        print('{\n    "api_token": "your-api-token-here"\n}')
        sys.exit(1)

def check_results_directory():
    """Create results directory if it doesn't exist."""
    if not os.path.exists('results'):
        os.makedirs('results')
        print("Created 'results' directory")

def perform_initial_checks():
    """Perform all initial checks."""
    check_python_version()
    check_config_exists()
    check_results_directory()

# Modify the main() function to include these checks:
async def main(iocs_file: str = None, device_names_file: str = None, emails_file: str = None):
    print(BANNER)
    perform_initial_checks()
    
    config = await load_config('config.json')
    api_token = config.get("api_token")
    
    if not api_token:
        logging.error("API token not found in config.json")
        return

    signal.signal(signal.SIGINT, handle_interrupt)

    if iocs_file:
        await process_iocs(iocs_file, api_token)
    elif device_names_file:
        await query_device_inventory(api_token, device_names_file)
    elif emails_file:
        await query_email_inventory(api_token, emails_file)  # Call the new function for email queries
    else:
        logging.error("No valid operation specified. Please use --iocs, --di, or --emails.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process Indicators of Compromise (IOCs), query Device Software Inventory, or query Device Events by email using the Microsoft Defender API.",
        epilog="Example usage:\n  python mdelh.py --iocs path/to/iocs.txt\n  python mdelh.py --di path/to/device_names.txt\n  python mdelh.py --emails path/to/emails.txt"
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
    parser.add_argument(
        '--emails',
        type=str,
        help='Path to the file containing email addresses (one per line).'
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Windows-specific event loop policy
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main(args.iocs, args.di, args.emails))  # Pass the emails file to the main function
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    except Exception as e:
        logging.error("An error occurred: %s", str(e))
