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
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    while True:  # Keep trying until success or fatal error
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(API_URL, headers=headers, json=payload) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 429:
                        error_json = await response.json()
                        wait_time = int(error_json.get("error", {}).get("message", "").split("in ")[-1].split(" ")[0])
                        logging.warning(f"Rate limit exceeded. Waiting {wait_time} seconds...")
                        try:
                            await asyncio.sleep(wait_time)
                        except asyncio.CancelledError:
                            logging.info("Query cancelled during rate limit wait")
                            return None
                        continue
                    elif response.status == 401:
                        raise APIUnauthorizedError("The API token is invalid or expired.")
                    else:
                        error_message = await response.text()
                        raise APIError(f"{response.status} - {error_message}")
        except asyncio.CancelledError:
            logging.info("Query cancelled by user")
            return None
        except Exception as e:
            logging.error(f"Query failed: {str(e)}")
            return None

async def fetch_device_software_inventory(api_token, device_inv):
    # Construct the KQL query
    kql_query = f"""
    DeviceTvmSoftwareInventory
    | where DeviceName contains "{device_inv}"
    | project DeviceId, DeviceName, SoftwareName, SoftwareVersion, OSPlatform, OSVersion
    | order by DeviceName asc
    """
    
    # Ensure the payload is correctly structured
    payload = {
        "Query": kql_query  # Ensure the query is included in the payload
    }
    
    return await execute_query(api_token, payload)  # Pass the payload to execute_query

async def fetch_accountupn(api_token, device_names_file: str):
    """Fetches the Account UPN for devices listed in the provided file."""
    if not os.path.isfile(device_names_file):
        logging.error(f"Device names file '%s' does not exist.")
        return None

    # Read device names from the file
    async with aiofiles.open(device_names_file, 'r') as file:
        device_names = [line.strip() for line in await file.readlines()]

    results = []  # To store results for each device
    successful_fetches = 0  # Counter for successful fetches
    total_devices = len(device_names)  # Total devices to process

    # Construct and execute the KQL query for each device name
    for device_name in device_names:
        kql_query = f"""
        DeviceInfo
        | where DeviceName startswith "{device_name}"
        | join kind=inner (DeviceLogonEvents | project DeviceId, InitiatingProcessAccountUpn) on DeviceId
        | distinct DeviceName, InitiatingProcessAccountUpn
        """
        
        # Ensure the payload is correctly structured
        payload = {
            "Query": kql_query  # Ensure the query is included in the payload
        }

        logging.info("Executing fetch_accountupn for device: %s", device_name)  # Log the device name being queried
        
        for attempt in range(5):  # Retry up to 5 times
            try:
                result = await execute_query(api_token, payload)  # Pass the payload to execute_query
                if result and "Results" in result:
                    logging.info("Successfully fetched AccountUpn for device: %s", device_name)  # Log success
                    results.append(result)  # Store the result for this device
                    successful_fetches += 1  # Increment successful fetch counter
                    break  # Exit the retry loop on success
                elif result and result.get("error", {}).get("code") == "TooManyRequests":
                    wait_time = int(result.get("error", {}).get("message", "60").split(" ")[-2])  # Extract wait time from message
                    logging.warning("Rate limit exceeded. Waiting for %d seconds before retrying...", wait_time)
                    await asyncio.sleep(wait_time)  # Wait before retrying
                else:
                    logging.warning("No results found for device: %s", device_name)  # Log if no results found
                    break  # Exit the retry loop on other errors

            except Exception as e:
                logging.error(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt == 4:  # Last attempt
                    logging.error("All retry attempts failed")

    # Write results to a CSV file
    results_file_path = "results/account_upn_results.csv"
    fieldnames = ["DeviceName", "AccountUpn"]  # Adjust based on the structure of your results

    async with aiofiles.open(results_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        await writer.writeheader()  # Write the header row

        for result in results:
            for item in result.get("Results", []):
                output_data = {
                    "DeviceName": item.get("DeviceName", ""),
                    "AccountUpn": item.get("InitiatingProcessAccountUpn", "")
                }
                await writer.writerow(output_data)  # Write each result to the CSV file

    logging.info("Results written to %s", results_file_path)  # Log the file path where results are saved

    # Log statistics after processing
    logging.info("Finished processing. Total devices: %d, Successful fetches: %d", total_devices, successful_fetches)
    return results  # Return all results collected

async def query_device_inventory(api_token, device_names_file):
    logging.info("Starting query_device_inventory with file: %s", device_names_file)  # Log start of function
    if not os.path.isfile(device_names_file):
        logging.error(f"Device names file '%s' does not exist.")
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
        logging.error(f"Failed to open file '%s' after multiple attempts.")
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

async def wait_if_needed():
    """Handles waiting based on rate limits."""
    global calls_made, start_time_minute, start_time_hour
    current_time = time.time()

    # Rate limiting logic
    if calls_made >= MAX_CALLS_PER_MINUTE:
        elapsed_time_minute = current_time - start_time_minute
        if elapsed_time_minute < 60:
            wait_time = 60 - elapsed_time_minute
            logging.info("Waiting for %d seconds to respect the rate limit...", wait_time)
            await asyncio.sleep(wait_time)
        start_time_minute = time.time()
        calls_made = 0

    if calls_made >= MAX_CALLS_PER_HOUR:
        elapsed_time_hour = current_time - start_time_hour
        if elapsed_time_hour < 3600:
            wait_time = 3600 - elapsed_time_hour
            logging.info("Waiting for %d seconds to respect the hourly rate limit...", wait_time)
            await asyncio.sleep(wait_time)
        start_time_hour = time.time()
        calls_made = 0

async def query_mde(session: aiohttp.ClientSession, api_token: str, query: str, retries: int = 10, backoff_factor: int = 5) -> Optional[dict]:
    global calls_made

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    query_data = {"Query": query}

    await wait_if_needed()  # Call the wait function before making the request

    for attempt in range(retries):
        try:
            async with session.post(API_URL, headers=headers, json=query_data) as response:
                if response.status == 401:
                    logging.error("API Key is deprecated. Please update the config.json file.")
                    sys.exit(1)
                elif response.status == 429:
                    # Get retry-after value from headers, default to calculated backoff
                    wait_time = int(response.headers.get("Retry-After", backoff_factor * (attempt + 1)))
                    logging.warning(f"Rate limit exceeded (429). Waiting {wait_time} seconds before retry {attempt + 1}/{retries}")
                    await asyncio.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                calls_made += 1
                return await response.json()
                
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                wait_time = int(e.headers.get("Retry-After", backoff_factor * (attempt + 1)))
                logging.warning(f"Rate limit exceeded (429). Waiting {wait_time} seconds before retry {attempt + 1}/{retries}")
                await asyncio.sleep(wait_time)
                continue
            logging.error(f"Request failed with status {e.status}: {str(e)}")
            
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == retries - 1:
                logging.error("All retry attempts failed")
                return None
            await asyncio.sleep(backoff_factor * (attempt + 1))
            
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

    async with aiohttp.ClientSession() as session:
        for item in items:
            if interrupt_occurred:
                logging.info("Exiting due to user interrupt during item processing.")
                return  # Exit the function gracefully
            logging.info("Processing item: %s", item)  # Log each item being processed
            # Replace process_item call with the actual query logic
            if not item:
                continue
                
            query = get_query(item)
            if query:
                query_count += 1
                result = await query_mde(session, api_token, query)
                if result and "Results" in result:
                    async with aiofiles.open(csv_file_path, 'a', newline='', encoding='utf-8') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        for res_item in result["Results"]:
                            await writer.writerow({
                                field: res_item.get(field, "") for field in fieldnames
                            })

        for query_type, count in query_counts.items():
            logging.info("Total queries for %s: %d", query_type, count)

        total_time = time.time() - start_time
        logging.info("Total execution time: %.2f seconds", total_time)
        logging.info("Total queries processed: %d", query_count)

        if query_count > 0 and critical_error_occurred:
            logging.error("Critical error occurred during processing.")

def handle_interrupt(loop):
    """Handle interrupt signal (Ctrl+C)"""
    global interrupt_occurred
    if not interrupt_occurred:  # Only print message on first interrupt
        interrupt_occurred = True
        print("\nReceived interrupt signal. Gracefully shutting down...")
        print("Press Ctrl+C again to force quit")
    else:
        print("\nForce quitting...")
        sys.exit(1)
    try:
        # Cancel all tasks
        for task in asyncio.all_tasks(loop):
            task.cancel()
        # Wait for all tasks to be cancelled
        loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks(), return_exceptions=True))
    except Exception as e:
        print(f"Error during shutdown: {e}")
    finally:
        # Ensure the loop is closed
        loop.close()
        sys.exit(0)  # Exit gracefully

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
    """Queries the Microsoft Security Center API for device events based on email addresses or usernames.

    Args:
        api_token: The API token for authentication.
        emails_file: The path to the file containing email addresses or usernames (one per line).

    Returns:
        None
    """
    if not os.path.isfile(emails_file):
        logging.error("Invalid email file provided. Please check the file path and try again.")
        return

    try:
        async with aiofiles.open(emails_file, 'r') as file:
            identifiers = [line.strip() for line in await file.readlines()]
    except Exception as e:
        logging.error("Error reading email file '%s': %s", emails_file, e)
        return

    results_folder = "results"
    os.makedirs(results_folder, exist_ok=True)
    csv_file_path = os.path.join(results_folder, "email_results.csv")  # Change the file name if needed

    # Initialize CSV file with headers, including Email/Username
    fieldnames = ["Identifier", "DeviceId", "DeviceName"]  # Changed Email to Identifier
    async with aiofiles.open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        await writer.writeheader()

    for identifier in identifiers:
        if '@' in identifier:
            username = identifier.split('@')[0]  # Extract the username from the email
        else:
            username = identifier  # Use the identifier as is if it's not an email

        logging.info("Querying for username: %s", username)  # Log each username being processed
        kql_query = f"""
        DeviceInfo 
        | where LoggedOnUsers contains "{username}"
        | distinct DeviceName
        """
        
        payload = {
            "Query": kql_query  # Ensure the query is included in the payload
        }
        
        result = await execute_query(api_token, payload)  # Execute the query
        if result and "Results" in result:
            logging.info("Results for %s: %s", username, result.get("Results", []))
            # Write results to CSV
            async with aiofiles.open(csv_file_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                for res_item in result["Results"]:
                    output_data = {
                        "Identifier": identifier,  # Include the original identifier in the output data
                        "DeviceId": res_item.get("DeviceId", ""),
                        "DeviceName": res_item.get("DeviceName", "")
                    }
                    await writer.writerow(output_data)  # Write each result immediately
        else:
            logging.info("No results found for username: %s", username)

# Add this after the imports
BANNER = r"""
███╗   ███╗██████╗ ███████╗██      ██╗  ██╗
████╗ ████║██╔══██╗██╔════╝██║     ██║  ██║
██╔████╔██║██║  ██║█████╗  ██║     ███████║
██║╚██╔╝██║██║  ██║██╔══╝  ██║     ██╔══██║
██║ ╚═╝ ██║██████╔╝███████╗███████╗██║  ██║
╚═╝     ╚═╝╚═════╚══════╝╚════╝╚═╝ ╚═╝  ╚═╝
------------------------------                                           
Microsoft Defender Lazy Hunter
Author: Aly Emara
Version: 1.0.1
------------------------------
"""

def check_python_version():
    """Validate if Python version is 3.7 or higher."""
    if sys.version_info < (3, 7):
        raise ValueError("Python 3.7 or higher is required")

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

def get_query(item: str) -> str:
    """Generate appropriate KQL query based on item type."""
    if is_sha256(item):
        query_counts["SHA256"] += 1
        return f"""DeviceFileEvents | where SHA256 == '{item}'"""
    elif is_sha1(item):
        query_counts["SHA1"] += 1
        return f"""DeviceFileEvents | where SHA1 == '{item}'"""
    elif is_md5(item):
        query_counts["MD5"] += 1
        return f"""DeviceFileEvents | where MD5 == '{item}'"""
    elif is_ipv4(item):
        query_counts["RemoteIP"] += 1
        return f"""DeviceNetworkEvents | where RemoteIP == '{item}'"""
    elif is_private_ipv4(item):
        query_counts["LocalIP"] += 1
        return f"""DeviceNetworkEvents | where LocalIP == '{item}'"""
    elif is_url(item) or is_hostname(item):
        query_counts["RemoteUrl"] += 1
        return f"""DeviceNetworkEvents | where RemoteUrl contains '{item}'"""
    return ""

# Modify the main() function to include these checks:
async def main(iocs_file: str = None, device_names_file: str = None, emails_file: str = None, api_key: str = None, dev_names_upn: str = None):
    """Main entry point for the script."""
    print(BANNER)
    perform_initial_checks()
    print(f"Arguments received: IOCs File={iocs_file}, Device Names File={device_names_file}, Emails File={emails_file}, API Key={str(api_key)[:10]}, Device Names UPN File={dev_names_upn}")
    # Update config.json with the new API key if provided
    if api_key:
        with open('config.json', 'r+') as config_file:
            config = json.load(config_file)
            config['api_token'] = api_key
            config_file.seek(0)  # Move to the beginning of the file
            json.dump(config, config_file, indent=4)
            config_file.truncate()  # Remove any leftover data
            logging.info("API key updated in config.json.")

    config = await load_config('config.json')
    api_token = config.get("api_token")
    
    if not api_token:
        logging.error("API token not found in config.json")
        return

    # Set up signal handlers
    signal.signal(signal.SIGINT, handle_interrupt)
    signal.signal(signal.SIGTERM, handle_interrupt)

    try:
        if iocs_file:
            await process_iocs(iocs_file, api_token)
        elif device_names_file:
            await query_device_inventory(api_token, device_names_file)
        elif emails_file:
            await query_email_inventory(api_token, emails_file)
        elif dev_names_upn:
            await fetch_accountupn(api_token, dev_names_upn)
        else:
            logging.error("No valid operation specified. Please use --iocs, --di, or --emails or --diupn.")
    except KeyboardInterrupt:
        logging.info("Script interrupted by user. Exiting...")
    except Exception as e:
        logging.error("An error occurred: %s", str(e))
    finally:
        if interrupt_occurred:
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process Indicators of Compromise (IOCs), query Device Software Inventory, or query Device Events by email using the Microsoft Defender API. or query AccountUPN from Device Name.",
        epilog="Example usage:\n  python mdelh.py --iocs path/to/iocs.txt\n  python mdelh.py --di path/to/device_names.txt\n  python mdelh.py --emails path/to/emails.txt\n --diupn path/to/device_names.txt"
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
    parser.add_argument(
        '--config',
        type=str,
        help='API key to update in config.json.'
    )
    parser.add_argument(
        '--diupn',
        type=str,
        help='Path to the file containing device names (one per line)'
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Windows-specific event loop policy
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main(args.iocs, args.di, args.emails, args.config, args.diupn))  # Pass the config argument to the main function
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    except Exception as e:
        logging.error("An error occurred: %s", str(e))
