import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import re
from dateutil.parser import parse
import pytz


API_URL = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"



def convert_to_cairo_time(timestamp_str):
  try:
    utc_dt = parse(timestamp_str)
    cairo_tz = pytz.timezone('Africa/Cairo')
    cairo_dt = utc_dt.astimezone(cairo_tz)
    # Strip everything after the decimal point
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
    # Basic URL validation, consider using a more robust URL validation library
    return bool(re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', value))

def query_mde(api_token, query):
    """Queries the MDE API with the given query.

    Args:
        api_token (str): The MDE API token.
        query (str): The KQL query to execute.

    Returns:
        dict: The JSON response from the MDE API, or None on error.
    """

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    query_data = {"Query": query}

    try:
        response = requests.post(API_URL, headers=headers, json=query_data)
        response.raise_for_status()  # Raise an exception for error HTTP status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying MDE: {e}")
        return None

def process_items(items, api_token, max_workers=10, backoff_time=1):
    """Processes items (hashes, IPs, URLs) and queries MDE asynchronously.

    Args:
        items (list): A list of items to search for.
        api_token (str): The MDE API token.
        max_workers (int, optional): The maximum number of concurrent workers. Defaults to 10.
        backoff_time (int, optional): The backoff time in seconds for rate limiting. Defaults to 1.
    """

    def build_query(item):
        if is_sha256(item):
            query = f"DeviceFileEvents | where SHA256 == '{item}'| limit 10 "
        elif is_sha1(item):
                    query = f"DeviceFileEvents | where SHA1 == '{item}'| limit 10 "
        elif is_md5(item):
                    query = f"DeviceFileEvents | where MD5 == '{item}'| limit 10 "
        elif is_ipv4(item):
            query = f"DeviceNetworkEvents | where RemoteIP == '{item}'| limit 10 "
        elif is_url:
            query = f"DeviceNetworkEvents | where RemoteUrl contains '{item}'| limit 10 "
        return query

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(query_mde, api_token, build_query(item)) for item in items]

        for future in futures:
            try:
                result = future.result()
                if result:
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
            except Exception as e:
                logging.error(f"Error processing results: {e}")
                time.sleep(backoff_time)

def main():
    # Replace with your API token
    api_token = "DEPRECATED"

    # Example usage:
    IOCs_file = "IOCs.txt"


    # Read items from files
    hashes = [line.strip() for line in open(IOCs_file)]

    # Process each item type
    process_items(hashes, api_token)

if __name__ == "__main__":
    main()
