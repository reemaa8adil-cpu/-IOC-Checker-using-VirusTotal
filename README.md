#IOC Checker using VirusTotal

#About
A cybersecurity project developed using Python and VirusTotal API to analyze Indicators of Compromise (IOCs) and classify them based on predefined trust criteria.

## Features
- Upload IOC files in CSV and Excel formats.
- Detect IP addresses, domains, and file hashes.
- Retrieve information using VirusTotal API.
- Classify IOCs as Trusted, Signed, or Not Trusted.
- Display scan results.
- Export untrusted IOCs as an Excel Block List.

#Technologies
- Python
- Streamlit
- VirusTotal API
- Pandas
- Requests

#How to Run
1. Clone the repository.
2. Install the required dependencies:
   `pip install -r requirements.txt`
3. Configure your VirusTotal API key as an environment variable.
4. Run the application:
   `streamlit run ioc.py`

