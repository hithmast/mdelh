import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import re
from dateutil.parser import parse
import pytz
import signal
import sys

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
        response.raise_for_status()  # Raise an exception for error HTTP status codes
        calls_made += 1
        return response.json()
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.ConnectionError) or isinstance(e, requests.exceptions.Timeout):
            logging.error(f"Network Error: {e}")
        else:
            logging.error(f"Error querying MDE: {e}")
        return None

def process_items(items, api_token, max_workers=10, backoff_time=1):
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
                if "Results" in result and result["Results"]:
                    for item in result["Results"]:
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
                    logging.info(f"No results found for query: {query}")
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

def handle_interrupt(signum, frame):
    logging.info("Script interrupted by user. Exiting...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, handle_interrupt)
    
    api_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IktRMnRBY3JFN2xCYVZWR0JtYzVGb2JnZEpvNCIsImtpZCI6IktRMnRBY3JFN2xCYVZWR0JtYzVGb2JnZEpvNCJ9.eyJhdWQiOiJodHRwczovL3NlY3VyaXR5Y2VudGVyLm1pY3Jvc29mdC5jb20vbXRwIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNDkxMzEzNmItYTYzMS00MjlmLTg2NDctYjIyMTE3NDQ5MjMxLyIsImlhdCI6MTcyNDAzNTc3NywibmJmIjoxNzI0MDM1Nzc3LCJleHAiOjE3MjQwNDEwNTIsImFjciI6IjEiLCJhaW8iOiJBVFFBeS84WEFBQUFVZVpGaDVaSzhrSlFsQS9KVmZhS2gyS1I2Y0FlaGR4WmpRNDNKclU1Q0phVzAzbm9ydVNEcFhPTm9lQzlPWmdJIiwiYW1yIjpbInB3ZCJdLCJhcHBfZGlzcGxheW5hbWUiOiJNaWNyb3NvZnQgMzY1IFNlY3VyaXR5IGFuZCBDb21wbGlhbmNlIENlbnRlciIsImFwcGlkIjoiODBjY2NhNjctNTRiZC00NGFiLTg2MjUtNGI3OWM0ZGM3Nzc1IiwiYXBwaWRhY3IiOiIyIiwiZmFtaWx5X25hbWUiOiJlenphdCIsImdpdmVuX25hbWUiOiJhbHkiLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiIxOTYuMjE5LjM5LjUwIiwibmFtZSI6ImFseSBlenphdCBtYWhtb3VkIGVtYXJhIiwib2lkIjoiM2Q1ZDMzYzQtY2JjNi00YjhmLTkxYzEtMjY0ZTg4MzFlMjdmIiwib25wcmVtX3NpZCI6IlMtMS01LTIxLTExOTM3NTYyMTItNDI0NzI0NDkwNy0zMTAwMDMxMDU4LTE1OTIzNCIsInB1aWQiOiIxMDAzMjAwMzZBNzFGRDE0IiwicmgiOiIwLkFRd0FheE1UU1RHbW4wS0dSN0loRjBTU01XVUVlUHdYSU5SQW9NVXdjQ0pIRzVJTUFENC4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJ1RDBiRmtyRkMyWnU2bTRudk5ZeHFhdk8tM20wN3FHMGZwTDhxbGk2UHowIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFGIiwidGlkIjoiNDkxMzEzNmItYTYzMS00MjlmLTg2NDctYjIyMTE3NDQ5MjMxIiwidW5pcXVlX25hbWUiOiJpdHMuYWxpLmVtYXJhQHRlLmVnIiwidXBuIjoiaXRzLmFsaS5lbWFyYUB0ZS5lZyIsInV0aSI6Il9KQmZwQ2YwdjA2enFLSW5wS05LQUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbImYyZWY5OTJjLTNhZmItNDZiOS1iN2NmLWExMjZlZTc0YzQ1MSIsImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfaWRyZWwiOiIxIDIyIn0.ubvmOtCoHi-A6mR0t_H94rXcyTJk1et6EutMzu7L8b8cF9XkUOdoRcvOqAUcY70hW0NrSgkDHy6cDPAwdXG_oJtGcdOUoGF2a26log5ORTWuL3I9RZJKuOPuvcTkTUmFQyEND23QJSIBWhVlbWr9GsvVK38SPzxiEYFnyd3i1Ps4du-dTxv5dVRH7YiX9610y1Ayc_A_O_ac2QlwtPPDVN6SzOaSvh8xRvvYOopfeQB2ngGM3_RA9PIVY4WO8qtdfPjATiVjuwqZIMvAY4p_uSVTrD2kkq4aaYZI5e-9MGHMjdow-FybE9XWnDy9CFuMro7x3-71Z9vqmfJE5wxOeQ"
    IOCs_file = "IOCs.txt"

    # Read items from file
    with open(IOCs_file, 'r') as file:
        hashes = [line.strip() for line in file]

    try:
        process_items(hashes, api_token)
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    finally:
        logging.info("Script finished or exited.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main()
