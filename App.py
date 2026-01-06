import streamlit as st
from streamlit_gsheets import GSheetsConnection

st.title("🛡️ Diagnosis Mode")

try:
    # 1. Print who the App thinks it is
    # We access secrets directly to see if they are loaded
    creds = st.secrets["connections"]["gsheets"]["service_account_info"]
    st.write(f"**App is trying to log in as:** `{creds['client_email']}`")
    st.write(f"**Using Key from Project:** `{creds['project_id']}`")

    # 2. Try to connect
    conn = st.connection("gsheets", type=GSheetsConnection)
    df = conn.read(worksheet="users", ttl=0)
    st.success("✅ Connection Successful! The Sheet is readable.")
    st.dataframe(df)

except Exception as e:
    st.error("❌ Connection Failed")
    st.write(f"**Error Message:** {e}")
    st.info("👇 CHECK THIS:")
    st.markdown("""
    1. Check the **Project ID** printed above. Does it match the Project where you enabled the APIs?
    2. Check the **Email** printed above. Is this EXACT email shared with your Google Sheet?
    """)
