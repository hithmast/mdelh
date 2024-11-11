import json
import aiohttp
import asyncio
import time
import logging
import re
from dateutil.parser import parse
import pytz
import signal
import sys
import os
import csv
import ipaddress
import aiofiles

API_URL = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

# Rate limits
MAX_CALLS_PER_MINUTE = 45
MAX_CALLS_PER_HOUR = 1500

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

def convert_to_cairo_time(timestamp_str):
    try:
        utc_dt = parse(timestamp_str)
        cairo_tz = pytz.timezone('Africa/Cairo')
        cairo_dt = utc_dt.astimezone(cairo_tz)
        cairo_dt_str = str(cairo_dt).split('.')[0]
        return f"{cairo_dt_str}"
    except ValueError as e:
        logging.error(f"Error converting timestamp: {timestamp_str}, Error: {e}")
        return None

def is_sha256(value):
    return len(value) == 64 and set(value.lower()).issubset("0123456789abcdef")

def is_sha1(value):
    return len(value) == 40 and set(value.lower()).issubset("0123456789abcdef")

def is_md5(value):
    return len(value) == 32 and set(value.lower()).issubset("0123456789abcdef")

def is_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        # Check if it's an IPv4 address and not a private IP
        return isinstance(ip, ipaddress.IPv4Address) and not ip.is_private
    except ValueError:
        return False

def is_private_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        # Check if it's an IPv4 address and is private
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_private
    except ValueError:
        return False
    
def is_url(value):
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

def is_hostname(value):
    if len(value) > 255:
        return False
    if value[-1] == ".":
        value = value[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in value.split("."))

async def query_mde(session, api_token, query, retries=5, backoff_factor=5):
    global calls_made, start_time_minute, start_time_hour

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    query_data = {"Query": query}

    current_time = time.time()

    # Check the minute rate limit
    if calls_made >= MAX_CALLS_PER_MINUTE:
        elapsed_time_minute = current_time - start_time_minute
        if elapsed_time_minute < 60:
            await asyncio.sleep(60 - elapsed_time_minute)
        start_time_minute = time.time()
        calls_made = 0

    # Check the hourly rate limit
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
                    print("API Key Is Deprecated. Add a new one to the config.json file.")
                    sys.exit(1)  # Exit the script
                response.raise_for_status()
                calls_made += 1
                return await response.json()
        except aiohttp.ClientError as e:
            logging.error(f"Error querying MDE: {e}")
            if response.status == 429:
                wait_time = backoff_factor * (attempt + 1)
                logging.error(f"Retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)
            else:
                break

    logging.error(f"No result returned for query: {query}")
    return None

async def process_items(items, api_token):
    query_count = 0
    critical_error_occurred = False
    
    query_mapping = {
        "SHA256": lambda item: f"""
            DeviceFileEvents
            | where SHA256 == '{item}'
            | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, FileSize, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine
            | limit 100
        """,
        "SHA1": lambda item: f"""
            DeviceFileEvents
            | where SHA1 == '{item}'
            | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, FileSize, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine
            | limit 100
        """,
        "MD5": lambda item: f"""
            DeviceFileEvents
            | where MD5 == '{item}'
            | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, FileSize, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine
            | limit 100
        """,
        "RemoteIP": lambda item: f"""
            DeviceNetworkEvents
            | where RemoteIP == '{item}'
            | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol
            | limit 100
        """,
        "RemoteUrl": lambda item: f"""
            DeviceNetworkEvents
            | where RemoteUrl contains '{item}'
            | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol
            | limit 100
        """,
        "LocalIP": lambda item: f"""
            DeviceNetworkEvents
            | where LocalIP == '{item}'
            | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol
            | limit 100
        """
    }

    results_folder = "results"
    os.makedirs(results_folder, exist_ok=True)
    csv_file_path = os.path.join(results_folder, "results.csv")

    def get_query(item):
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
            logging.warning(f"Invalid item format: {item}")
            return None

    async def process_item(session, item):
        nonlocal query_count, critical_error_occurred
        if critical_error_occurred:
            return
        
        query = get_query(item)
        if not query:
            return
        
        query_count += 1
        result = await query_mde(session, api_token, query)
        if result is None:
            logging.error(f"Failed to get result for query: {query}. Stopping further processing.")
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
                    await writer.writeheader()

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
                    await writer.writerow(output_data)
        else:
            logging.info(f"No results found for query: {query}")

    start_time = time.time()

    async with aiohttp.ClientSession() as session:
        for item in items:
            await process_item(session, item)

    # Log the number of queries for each type
    for query_type, count in query_counts.items():
        logging.info(f"Total queries for {query_type}: {count}")

    total_time = time.time() - start_time
    logging.info(f"Total execution time: {total_time:.2f} seconds")
    logging.info(f"Total queries processed: {query_count}")

def handle_interrupt(signum, frame):
    logging.info("Script interrupted by user. Exiting...")
    sys.exit(0)

async def main():
    """ Main function that sets up the signal handler, loads API token from configuration file, reads IOCs file, and processes the items. """
    signal.signal(signal.SIGINT, handle_interrupt)
    # Load API key from configuration file
    def load_config(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    
    config = load_config('config.json')
    api_token = config.get("api_token")
    
    iocs_file = input("Please enter IOCs File : ")

    # Read items from file
    with open(iocs_file, 'r') as file:
        hashes = [line.strip() for line in file]

    try:
        await process_items(hashes, api_token)
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    finally:
        logging.info("Script finished or exited.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    asyncio.run(main())
