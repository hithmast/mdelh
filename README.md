## Overview

The MDE Lazy Hunter Script interacts with the Microsoft Defender for Endpoint (MDE) API, enabling users to query the service for various types of data. It supports six types of inputs: URLs, IP addresses, domains, and file hashes (SHA256, SHA1, MD5). Results are processed asynchronously, timestamps are converted to Cairo time, and output can be saved to a CSV file.

## Features

- **MDE Querying**: Queries the Microsoft Defender for Endpoint API using provided KQL queries.
- **Timestamp Conversion**: Converts UTC timestamps to Cairo local time.
- **Input Validation**: Validates SHA256, SHA1, MD5, IPv4 addresses, URLs, and domains.
- **Asynchronous Processing**: Utilizes multi-threading to process multiple queries concurrently.
- **Rate Limiting**: Adheres to API rate limits of up to 45 calls per minute and up to 1,500 calls per hour to ensure compliance and prevent overloading the service.
- **CSV Output**: Results are saved to a CSV file in the `results` folder if any results are obtained.

## Prerequisites

- Python 3.6 or higher
- `requests` library
- `dateutil` library
- `pytz` library
- `concurrent.futures` for threading support
- `csv` library (included in Python standard library)

Install the required libraries using:

```bash
pip install -r requirements.txt
```

## Obtaining the API Key

To obtain the API key required to run the script, follow these steps:

1. Visit the [Microsoft Defender API Explorer](https://security.microsoft.com/interoperability/api-explorer).
2. Open the Network inspection tool in your browser (e.g., by pressing F12 and navigating to the "Network" tab).
3. Run a query test in the API Explorer.
4. Find the request made by the API Explorer and look for the authorization header in the request details.
5. Copy the API key found in this header (excluding the "Bearer" prefix) and paste it into the `api_token` variable in the script.

## Script Usage

1. **API Token**: Replace the placeholder in the `api_token` variable with your actual MDE API token obtained from the steps above.
2. **Input Data**: Prepare a list of items (e.g., URLs, IP addresses, domains, file hashes) in a text file (`IOCs.txt`), with each item on a new line.
3. **Run the Script**: Execute the script by running:
   ```bash
   python mdelh.py
   ```

## Functions

- `convert_to_cairo_time(timestamp_str)`: Converts a UTC timestamp to Cairo local time.
- `is_sha256(value)`, `is_sha1(value)`, `is_md5(value)`: Validates whether a string is a valid SHA256, SHA1, or MD5 hash, respectively.
- `is_ipv4(value)`: Validates whether a string is a valid IPv4 address.
- `is_url(value)`: Performs basic URL validation.
- `is_hostname(value)`: Validates a hostname based on standard DNS rules.
- `query_mde(api_token, query)`: Sends a query to the MDE API and returns the JSON response.
- `process_items(items, api_token, max_workers=10, backoff_time=1)`: Processes a list of items asynchronously, queries the MDE API, and outputs the results to both the console and a CSV file.

## Example

This example demonstrates how to use the script:

1. **Prepare Input File**: Create an `IOCs.txt` file containing the following data:
   ```
   0ab2ff188e8e6d624b60f6c164c4759a09079fe5
   43b9bc43eee4c0e034ec44d5ca8188d015dc473c2e535e89e3d1c3e7541b11af
   7fae200181be69d91051efc570b665ac
   192.168.1.1
   google.com
   https://bing.com
   ```
2. **Run the Script**:
   ```bash
   python mdelh.py
   ```

**Expected Output**: The script will output results from the MDE API to both the console and a CSV file in the `results` folder, with timestamps converted to Cairo time.

## Logging and Error Handling

- The script logs any errors encountered during API queries or result processing using Python's logging module.
- If an error occurs during processing, the script will wait for a specified backoff time before retrying.

## Rate Limits

The script adheres to the following API rate limits:

- **Up to 45 calls per minute**: The script will automatically pause if this limit is reached within a minute.
- **Up to 1,500 calls per hour**: The script will automatically pause if this limit is reached within an hour.

These limits are enforced to ensure compliance with API usage policies and to prevent overloading the service.

## Notes

- Ensure your API token has the necessary permissions to query the MDE API.
- This script is intended for educational purposes. Use it responsibly, especially when handling sensitive data.

## Future Updates

- **Enhanced CSV Output**: Implement functionality to include additional fields and data validation in the CSV output.
- **Improved Logging**: Add comprehensive logging to capture output details and errors, providing better traceability and debugging capabilities.

## Limitations

- **Query Timeframe**: You can only run a query on data from the last 30 days.
- **Result Size**: The results include a maximum of 100,000 rows.
- **Execution Limits**:
  - **API Calls**: Up to 45 calls per minute, and up to 1,500 calls per hour.
  - **Execution Time**: 10 minutes of running time every hour and 3 hours of running time a day.
  - The maximal execution time of a single request is 200 seconds.
- **429 Response**: A 429 response indicates that the quota limit has been reached, either by the number of requests or by CPU usage. Check the response body to understand which limit was exceeded.
- **Query Result Size**: The maximum query result size of a single request cannot exceed 124 MB. If exceeded, an HTTP 400 Bad Request will be returned with the message "Query execution has exceeded the allowed result size. Optimize your query by limiting the number of results and try again."

## License

This script is provided under the MIT License. See `LICENSE` for details.
