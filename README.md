## Overview

The MDE Lazy Hunter Script interacts with the Microsoft Defender for Endpoint (MDE) API, allowing users to query the service for various types of data. It supports six types of inputs: URLs, IP addresses, domains, and file hashes (SHA256, SHA1, MD5). The results are processed asynchronously, with timestamp conversion to Cairo time, and displayed in a structured format.

## Features

- **MDE Querying**: The script queries the Microsoft Defender for Endpoint API using provided KQL queries.
- **Timestamp Conversion**: Converts UTC timestamps to Cairo local time.
- **Input Validation**: Supports validation for SHA256, SHA1, MD5, IPv4 addresses, URLs, and domains.
- **Asynchronous Processing**: Uses multi-threading to process multiple queries concurrently.

## Prerequisites

- Python 3.6 or higher
- `requests` library
- `dateutil` library
- `pytz` library
- `concurrent.futures` for threading support

You can install the required libraries using:

```bash
pip install -r requirements.txt
```

## Obtaining the API Key

To obtain the API key required to run the script, follow these steps:

1. Visit [Microsoft Defender API Explorer](https://security.microsoft.com/interoperability/api-explorer).
2. Open the Network inspection tool in your browser (e.g., by pressing `F12` and navigating to the "Network" tab).
3. Run a query test in the API Explorer.
4. Find the request made by the API Explorer and look for the `authorization` header in the request details.
5. Copy the API key found in this header without bearer word and paste it into the `api_token` variable in the script.

## Script Usage

1. **API Token**: Replace the placeholder in the `api_token` variable with your actual MDE API token obtained from the steps above.
2. **Input Data**: Prepare a list of items (e.g., URLs, IP addresses, domains, file hashes) in a text file (`IOCs.txt`) with each item on a new line.
3. **Run the Script**: Execute the script by running:

```bash
python MDELH.py
```

## Functions

### `convert_to_cairo_time(timestamp_str)`
Converts a UTC timestamp to Cairo local time.

### `is_sha256(value)`, `is_sha1(value)`, `is_md5(value)`
Validates whether a string is a valid SHA256, SHA1, or MD5 hash, respectively.

### `is_ipv4(value)`
Validates whether a string is a valid IPv4 address.

### `is_url(value)`
Performs basic URL validation.

### `is_domain(value)`
Performs basic domain validation using regex.

### `query_mde(api_token, query)`
Sends a query to the MDE API and returns the JSON response.

### `process_items(items, api_token, max_workers=10, backoff_time=1)`
Processes a list of items asynchronously, queries the MDE API, and outputs the results.

## Example

This example demonstrates how to use the script:

1. **Prepare Input File**: Create a `IOCs.txt` file containing the following data:
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
   python MDELH.py
   ```

3. **Expected Output**: The script will output results from the MDE API, with timestamps converted to Cairo time.

## Logging and Error Handling

- The script logs any errors encountered during API queries or result processing using Python's `logging` module.
- If an error occurs during processing, the script will wait for a specified backoff time before retrying.

## Notes

- Ensure your API token has the necessary permissions to query the MDE API.
- This script is intended for educational purposes. Use it responsibly, especially when handling sensitive data.

Here's the section for the `README.md` file:

---

## Future Updates

- **CSV Output**: Implement functionality to write query results to a CSV file for easier data management and analysis.
- **Logging**: Add comprehensive logging to capture output details and errors, providing better traceability and debugging capabilities.
  
## License

This script is provided under the MIT License. See `LICENSE` for details.
