import streamlit as st
import pandas as pd
import requests
import time
import re
import io
import zipfile

# ====== Config ======
API_KEY = "f5b6239599f169bb9dfb40eb25a7caecc9985ce9f5512e98f2be40be6b598465"
HEADERS = {"x-apikey": API_KEY}

# ====== Helper Functions ======
def detect_type(ioc):
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
        return "ip"
    elif re.match(r'^[A-Fa-f0-9]{32}$', ioc) or re.match(r'^[A-Fa-f0-9]{40}$', ioc) or re.match(r'^[A-Fa-f0-9]{64}$', ioc):
        return "hash"
    else:
        return "domain"

def vt_request(endpoint):
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=20)
    except Exception:
        return {}
    if resp.status_code == 429:
        time.sleep(15)
        resp = requests.get(url, headers=HEADERS, timeout=20)
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

# ====== Streamlit App ======
st.title("🔍 IOC Checker using VirusTotal")
st.write(
    "Upload your Excel (.xlsx) or CSV (UTF-8 or Latin) file. "
    "The app will automatically check each IOC and split results into Saudi/Trusted vs Others."
)

uploaded = st.file_uploader("📁 Upload your file here", type=["xlsx", "csv"])

if uploaded:
    # Read file (handle encoding safely)
    if uploaded.name.endswith(".xlsx"):
        df = pd.read_excel(uploaded)
    else:
        try:
            df = pd.read_csv(uploaded, encoding="utf-8")
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(uploaded, encoding="latin1")
            except Exception:
                df = pd.read_csv(uploaded, encoding="cp1256")

    st.write("📋 File preview:")
    st.dataframe(df.head())

    # Detect IOC column
    col = None
    for c in df.columns:
        if c.lower() in ["ioc", "domain", "url", "hash", "ip"]:
            col = c
            break

    if not col:
        st.error("❌ Could not find IOC column. Try naming it 'IOC' or 'Domain'.")
    else:
        iocs = df[col].dropna().astype(str).tolist()
        st.info(f"Found {len(iocs)} IOCs to check...")

        pos_rows, other_rows = [], []
        progress = st.progress(0)

        for i, ioc in enumerate(iocs, 1):
            ioc_type = detect_type(ioc)
            result = ""

            try:
                if ioc_type == "ip":
                    result = "Saudi IP ✅" if check_ip(ioc) else "Not Saudi"
                elif ioc_type == "domain":
                    result = "Saudi Domain ✅" if check_domain(ioc) else "Not Saudi Domain"
                elif ioc_type == "hash":
                    result = "Signed File ✅" if check_hash(ioc) else "Unsigned"
                else:
                    result = "Unknown Type"
            except Exception as e:
                result = f"Error: {e}"

            row = {"IOC": ioc, "Type": ioc_type, "Result": result}

            # Positive condition
            if ("Saudi" in result) or ("Signed File" in result):
                pos_rows.append(row)
            else:
                other_rows.append(row)

            progress.progress(i / len(iocs))
            time.sleep(1)

        pos_df = pd.DataFrame(pos_rows)
        other_df = pd.DataFrame(other_rows)

        st.success("✅ Scan complete!")
        st.write(f"Saudi/Trusted: {len(pos_df)} | Others: {len(other_df)}")

        with st.expander("🟢 Saudi / Trusted Results"):
            st.dataframe(pos_df if not pos_df.empty else pd.DataFrame(["No positives found."]))

        with st.expander("⚪ Other IOCs"):
            st.dataframe(other_df if not other_df.empty else pd.DataFrame(["No other IOCs found."]))

        # Create Excel files in memory
        def to_excel_bytes(df):
            buf = io.BytesIO()
            df.to_excel(buf, index=False, engine="openpyxl")
            buf.seek(0)
            return buf

        pos_buf = to_excel_bytes(pos_df)
        other_buf = to_excel_bytes(other_df)

        # Combine both into a single ZIP
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr("Saudi_IOCs.xlsx", pos_buf.getvalue())
            zipf.writestr("Other_IOCs.xlsx", other_buf.getvalue())
        zip_buf.seek(0)

        st.download_button(
            "⬇️ Download All Results (ZIP)",
            data=zip_buf,
            file_name="IOC_Results.zip",
            mime="application/zip",
        )

