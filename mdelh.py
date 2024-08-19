import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import re
from dateutil.parser import parse
import pytz

API_URL = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

# Rate limits
MAX_CALLS_PER_MINUTE = 45
MAX_CALLS_PER_HOUR = 1500

calls_made = 0
start_time_minute = time.time()
start_time_hour = time.time()

def convert_to_cairo_time(timestamp_str):
    try:
        utc_dt = parse(timestamp_str)
        cairo_tz = pytz.timezone('Africa/Cairo')
        cairo_dt = utc_dt.astimezone(cairo_tz)
        cairo_dt_str = str(cairo_dt).split('.')[0]
        return f"TimeStamp: {cairo_dt_str}"
    except ValueError as e:
        print(f"Error converting timestamp: {timestamp_str}, Error: {e}")
        return None

def is_sha256(value):
    return len(value) == 64 and set(value.lower()).issubset("0123456789abcdef")

def is_sha1(value):
    return len(value) == 40 and set(value.lower()).issubset("0123456789abcdef")

def is_md5(value):
    return len(value) == 32 and set(value.lower()).issubset("0123456789abcdef")

def is_ipv4(value):
    try:
        import ipaddress
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False

def is_url(value):
    return bool(re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', value))

def query_mde(api_token, query):
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
            time.sleep(60 - elapsed_time_minute)
        start_time_minute = time.time()
        calls_made = 0

    # Check the hourly rate limit
    if calls_made >= MAX_CALLS_PER_HOUR:
        elapsed_time_hour = current_time - start_time_hour
        if elapsed_time_hour < 3600:
            time.sleep(3600 - elapsed_time_hour)
        start_time_hour = time.time()
        calls_made = 0

    try:
        response = requests.post(API_URL, headers=headers, json=query_data)
        if response.status_code == 429:
            # Handle rate limiting with exponential backoff
            retry_after = int(response.headers.get('Retry-After', 1))  # Default to 1 second if not provided
            logging.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds.")
            time.sleep(retry_after)
            return query_mde(api_token, query)
        response.raise_for_status()  # Raise an exception for error HTTP status codes
        calls_made += 1
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying MDE: {e}")
        return None

def process_items(items, api_token, max_workers=1, backoff_time=1):
    def build_query(item):
        if is_sha256(item):
            query = f"DeviceFileEvents | where SHA256 == '{item}'| limit 10 "
        elif is_sha1(item):
            query = f"DeviceFileEvents | where SHA1 == '{item}'| limit 10 "
        elif is_md5(item):
            query = f"DeviceFileEvents | where MD5 == '{item}'| limit 10 "
        elif is_ipv4(item):
            query = f"DeviceNetworkEvents | where RemoteIP == '{item}'| limit 10 "
        elif is_url(item):
            query = f"DeviceNetworkEvents | where RemoteUrl contains '{item}'| limit 10 "
        else:
            logging.warning(f"Invalid item format: {item}")
            return None
        return query

    def process_item(item):
        query = build_query(item)
        if query:
            result = query_mde(api_token, query)
            if result:
                for item in result.get("Results", []):
                    output_data = {
                        "Timestamp": convert_to_cairo_time(item.get("Timestamp", "")),
                        "DeviceName": item.get("DeviceName", ""),
                        "DeviceId": item.get("DeviceId", ""),
                        "RemoteIP": item.get("RemoteIP", ""),
                        "RemoteUrl": item.get("RemoteUrl", ""),
                        "FileName": item.get("FileName", ""),
                        "FilePath": item.get("FilePath", ""),
                        "FileSize": item.get("FileSize", ""),
                        "SHA256": item.get("SHA256", ""),
                        "SHA1": item.get("SHA1", ""),
                        "FileType": item.get("FileType", "")
                    }
                    output_str = ", ".join(f"{key}: {value}" for key, value in output_data.items() if value)
                    print(output_str)
            else:
                logging.error(f"No result returned for query: {query}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_item, item) for item in items]

        for future in futures:
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing result: {e}")
                time.sleep(backoff_time)

def main():
    api_token = "YOUR_API_TOKEN_HERE"
    IOCs_file = "IOCs.txt"

    # Read items from file
    with open(IOCs_file, 'r') as file:
        hashes = [line.strip() for line in file]

    process_items(hashes, api_token)

if __name__ == "__main__":
    main()
