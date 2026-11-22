# IOC Checker using VirusTotal

## About
A cybersecurity project developed using Python and VirusTotal API to analyze Indicators of Compromise (IOCs) and classify them based on predefined trust criteria.

## Features
- Upload IOC files in CSV and Excel formats.
- Detect IP addresses, domains, and file hashes.
- Retrieve information using VirusTotal API.
- Classify IOCs as Trusted, Signed, or Not Trusted.
- Display scan results.
- Export untrusted IOCs as an Excel Block List.

## Technologies
- Python
- Streamlit
- VirusTotal API
- Pandas
- Requests

## How to Run
1. Clone the repository.
2. Install the required dependencies:
   `pip install -r requirements.txt`
3. Configure your VirusTotal API key as an environment variable.
4. Run the application:
   `streamlit run ioc.py`

<img width="1080" height="720" alt="Screenshot 2026-11-22 190242" src="https://github.com/user-attachments/assets/f7c2e70f-642a-4207-927c-412f8fb6a1ab" />
<img width="1080" height="720" alt="Screenshot 2026-11-22 190533" src="https://github.com/user-attachments/assets/8862906a-5bf4-4deb-9091-729c6b9f47d7" />
<img width="1080" height="720" alt="Screenshot 2026-11-22 190627" src="https://github.com/user-attachments/assets/54d2b1de-94dd-4586-b8ee-9ba7b5e7d385" />

