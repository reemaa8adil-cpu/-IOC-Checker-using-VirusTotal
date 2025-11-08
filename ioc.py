import streamlit as st
import pandas as pd
import requests
import time
import re
import os

API_KEY = "f5b6239599f169bb9dfb40eb25a7caecc9985ce9f5512e98f2be40be6b598465"
HEADERS = {"x-apikey": API_KEY}

# ============ Helpers ============
def detect_type(ioc):
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
        return "ip"
    elif re.match(r'^[A-Fa-f0-9]{32}$', ioc) or re.match(r'^[A-Fa-f0-9]{40}$', ioc) or re.match(r'^[A-Fa-f0-9]{64}$', ioc):
        return "hash"
    else:
        return "domain"

def vt_request(endpoint):
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 429:
        time.sleep(15)
        resp = requests.get(url, headers=HEADERS)
    return resp.json() if resp.status_code == 200 else {}

def check_ip(ioc):
    data = vt_request(f"ip_addresses/{ioc}")
    country = data.get("data", {}).get("attributes", {}).get("country")
    return country == "SA"

def check_domain(ioc):
    if ioc.lower().endswith(".sa"):
        return True
    data = vt_request(f"domains/{ioc}")
    reg_country = (
        data.get("data", {})
        .get("attributes", {})
        .get("registrant", {})
        .get("country")
    )
    return reg_country in ["SA", "Saudi Arabia"]

def check_hash(ioc):
    data = vt_request(f"files/{ioc}")
    attrs = data.get("data", {}).get("attributes", {})
    pe_info = attrs.get("pe_info", {})
    signers = pe_info.get("signers")
    return bool(signers)

# ============ Streamlit Interface ============
st.title("🔍 IOC Checker using VirusTotal")
st.write("Upload your file (Excel or CSV) to automatically check IOCs via VirusTotal.")

uploaded = st.file_uploader("Upload your file here", type=["xlsx", "csv"])

if uploaded:
    df = pd.read_excel(uploaded) if uploaded.name.endswith(".xlsx") else pd.read_csv(uploaded)
    st.write("📋 Preview of your file:")
    st.dataframe(df.head())

    col = None
    for c in df.columns:
        if c.lower() in ["ioc", "domain", "url", "hash", "ip"]:
            col = c
            break
    if not col:
        st.error("Could not find an IOC column (try naming it 'IOC' or 'Domain').")
    else:
        results = []
        progress = st.progress(0)
        for i, ioc in enumerate(df[col].dropna().astype(str).tolist(), 1):
            ioc_type = detect_type(ioc)
            result = {"IOC": ioc, "Type": ioc_type, "Result": ""}
            try:
                if ioc_type == "ip":
                    result["Result"] = "Saudi IP ✅" if check_ip(ioc) else "Not Saudi"
                elif ioc_type == "domain":
                    result["Result"] = "Saudi Domain ✅" if check_domain(ioc) else "Not Saudi Domain"
                elif ioc_type == "hash":
                    result["Result"] = "Signed File ✅" if check_hash(ioc) else "Unsigned"
                else:
                    result["Result"] = "Unknown Type"
            except Exception as e:
                result["Result"] = f"Error: {e}"
            results.append(result)
            progress.progress(i / len(df))
            time.sleep(1)

        res_df = pd.DataFrame(results)
        st.success("✅ Scanning complete!")
        st.dataframe(res_df)

        out_name = "Scan_Results.xlsx"
        res_df.to_excel(out_name, index=False)
        with open(out_name, "rb") as f:
            st.download_button("⬇️ Download Results as Excel", f, file_name=out_name)
