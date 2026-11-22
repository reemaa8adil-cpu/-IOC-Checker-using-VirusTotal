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
<img width="1080" height="610" alt="Screenshot 2026-11-22 190242" src="https://github.com/user-attachments/assets/b8c0ad88-5ea3-4f07-8e69-d34ebd806a32" />
<img width="1080" height="635" alt="Screenshot 2026-11-22 190533" src="https://github.com/user-attachments/assets/38a2f48f-1141-4118-90ea-7155a9a06387" />
<img width="1080" height="636" alt="Screenshot 2026-11-22 190627" src="https://github.com/user-attachments/assets/b3aabbff-baac-43a0-b45e-193cc11cf40c" />

