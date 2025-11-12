import streamlit as st
import pandas as pd
import requests
import time
import re
import io

# ====== Config ======
API_KEY = "f5b6239599f169bb9dfb40eb25a7caecc9985ce9f5512e98f2be40be6b598465"
HEADERS = {"x-apikey": API_KEY}
SLEEP_SECONDS = 0.8

# ====== Helper Functions ======
def detect_type(ioc: str) -> str:
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
        return "IP"
    if re.match(r'^[A-Fa-f0-9]{32}$', ioc) or re.match(r'^[A-Fa-f0-9]{40}$', ioc) or re.match(r'^[A-Fa-f0-9]{64}$', ioc):
        return "HASH"
    return "DOMAIN"

def vt_request(endpoint: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=20)
    except Exception:
        return {}
    if resp.status_code == 429:
        time.sleep(15)
        try:
            resp = requests.get(url, headers=HEADERS, timeout=20)
        except Exception:
            return {}
    if resp.status_code != 200:
        return {}
    try:
        return resp.json()
    except Exception:
        return {}

def check_ip(ioc: str) -> bool:
    data = vt_request(f"ip_addresses/{ioc}")
    return data.get("data", {}).get("attributes", {}).get("country") == "SA"

def check_domain(ioc: str) -> bool:
    if ioc.lower().endswith(".sa"):
        return True
    data = vt_request(f"domains/{ioc}")
    reg_country = data.get("data", {}).get("attributes", {}).get("registrant", {}).get("country")
    return reg_country in ["SA", "Saudi Arabia"]

def check_hash(ioc: str) -> bool:
    data = vt_request(f"files/{ioc}")
    attrs = data.get("data", {}).get("attributes", {})
    full_text = str(attrs).lower()
    pe_info = str(attrs.get("pe_info", {})).lower()
    keywords = ["signed", "signature valid", "certificate", "authenticode", "signer", "digital signature", "verified", "microsoft"]
    return any(k in full_text or k in pe_info for k in keywords)

# ====== Streamlit App ======
st.title("🔍 IOC Checker using VirusTotal")
st.write("Upload your IOC file to classify each IOC as **Trusted**, **Signed**, or **Not Trusted**.")

uploaded = st.file_uploader("📁 Upload file (.xlsx or .csv)", type=["xlsx", "csv"])

if uploaded:
    # Read file safely
    try:
        if uploaded.name.endswith(".xlsx"):
            df = pd.read_excel(uploaded)
        else:
            df = pd.read_csv(uploaded, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(uploaded, encoding="latin1")

    st.write("📋 File Preview:")
    st.dataframe(df.head())

    # Find IOC column
    col = None
    for c in df.columns:
        if c.lower() in ["ioc", "domain", "url", "hash", "ip", "value"]:
            col = c
            break

    if not col:
        st.error("❌ Could not find IOC column. Please name it 'IOC', 'Domain', 'Hash', or 'IP'.")
        st.stop()

    iocs = df[col].dropna().astype(str).tolist()
    total = len(iocs)
    st.info(f"🔎 Checking {total} IOCs... Please wait.")
    progress = st.progress(0)

    trusted_rows = []
    block_rows = []

    for idx, ioc in enumerate(iocs, start=1):
        ioc_type = detect_type(ioc)
        trusted_status = "Not Trusted"

        try:
            if ioc_type == "IP" and check_ip(ioc):
                trusted_status = "Trusted"
            elif ioc_type == "DOMAIN" and check_domain(ioc):
                trusted_status = "Trusted"
            elif ioc_type == "HASH" and check_hash(ioc):
                trusted_status = "Signed"
        except Exception:
            trusted_status = "Not Trusted"

        row = {"IOC": ioc, "Type": ioc_type, "Trusted": trusted_status}

        if trusted_status in ["Trusted", "Signed"]:
            trusted_rows.append(row)
        else:
            block_rows.append(row)

        progress.progress(idx / total)
        time.sleep(SLEEP_SECONDS)

    st.success("✅ Scan Complete!")

    trusted_df = pd.DataFrame(trusted_rows)
    block_df = pd.DataFrame(block_rows)

    st.write(f"🟢 Trusted: {len(trusted_df)} | 🔴 Block List: {len(block_df)}")

    # Show Trusted results
    st.subheader("✅ Trusted IOCs")
    st.dataframe(trusted_df if not trusted_df.empty else pd.DataFrame(["No Trusted IOCs found."]))

    # Show Block List results + download
    st.subheader("🔴 Block List")
    if not block_df.empty:
        st.dataframe(block_df)
        buf = io.BytesIO()
        block_df.to_excel(buf, index=False, engine="openpyxl")
        buf.seek(0)
        st.download_button("⬇️ Download Block List (Excel)", buf, "Block_List.xlsx")
    else:
        st.info("No Blocked IOCs found.")
