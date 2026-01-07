import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib
from datetime import datetime, timedelta
from fpdf import FPDF

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️", layout="wide")

# --- ASSETS & FUNCTIONS ---
def generate_certificate(username, filename, file_hash, timestamp):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 24)
    pdf.cell(0, 20, "Certificate of Registration", ln=True, align='C')
    
    pdf.set_font("Arial", size=12)
    pdf.ln(20)
    pdf.cell(0, 10, f"This document certifies that the file listed below", ln=True, align='C')
    pdf.cell(0, 10, f"has been secured on the Creator Shield Blockchain.", ln=True, align='C')
    
    pdf.ln(20)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(50, 10, "Owner:", border=0)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"{username}", ln=True)
    
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(50, 10, "File Name:", border=0)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"{filename}", ln=True)
    
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(50, 10, "Timestamp (IST):", border=0)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"{timestamp}", ln=True)
    
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Digital Fingerprint (SHA-256):", ln=True)
    pdf.set_font("Courier", size=10)
    pdf.multi_cell(0, 10, file_hash)
    
    pdf.ln(30)
    pdf.set_font("Arial", 'I', 10)
    pdf.cell(0, 10, "Creator Shield - Intellectual Property Protection Service", ln=True, align='C')
    
    return pdf.output(dest='S').encode('latin-1')

# --- CONNECT TO DATABASE ---
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
    db_active = True
except:
    db_active = False

# --- SESSION STATE ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""

# --- AUTHENTICATION ---
if not st.session_state.login:
    
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.title("🛡️ Creator Shield")
    
    tab_login, tab_register = st.tabs(["Sign In", "Create Account"])
    
    # 1. SIGN IN PAGE
    with tab_login:
        st.write("### Welcome Back")
        email = st.text_input("Email Address", key="login_email")
        password = st.text_input("Password", type="password", key="login_pass")
        
        col_login, col_forgot = st.columns([1, 2])
        with col_login:
            if st.button("Sign In", type="primary", use_container_width=True):
                
                # --- MASTER LOGIN (FOUNDER - UNLIMITED) ---
                if email == "founder@creatorshield.in" and password == "admin@#":
                    st.session_state.login = True
                    st.session_state.user = email
                    st.rerun()
                
                # --- USER LOGIN (DATABASE) ---
                elif db_active:
                    try:
                        df = conn.read(worksheet="users", ttl=0)
                        df = df.dropna(how="all")
                        if not df.empty and ((df['username'] == email) & (df['password'] == password)).any():
                            st.session_state.login = True
                            st.session_state.user = email
                            st.rerun()
                        else:
                            st.error("Incorrect email or password.")
                    except:
                        st.error("System Offline. Login with Master Key.")
                else:
                     st.error("System Offline.")
        
        with col_forgot:
            st.markdown("""
            <div style="text-align: right; padding-top: 10px;">
                <a href="mailto:support@creatorshield.in?subject=Reset Password" style="text-decoration: none; color: #FF4B4B;">Forgot Password?</a>
            </div>
            """, unsafe_allow_html=True)

    # 2. REGISTRATION PAGE
    with tab_register:
        st.write("### Join Creator Shield")
        st.write("To create an account, please fill out the secure application form below.")
        st.write("") 
        
        st.link_button("📝 Secure Your Data (Form)", "https://docs.google.com/forms/d/e/1FAIpQLSdeP0149pOVn8GmQ5dkpjbcC8uPYK_sWpAPGxI8JXbCDHABUw/viewform?usp=header", type="primary", use_container_width=True)
        
        st.divider()
        st.write("For Admin Use Only (Manual Add):")
        # I kept this simple manual adder in case you want to test right now
        new_u = st.text_input("New Email", key="new_u")
        new_p = st.text_input("New Password", type="password", key="new_p")
        if st.button("Create User (3 Credits)"):
            if db_active:
                try:
                    df = conn.read(worksheet="users", ttl=0)
                    # HERE IS THE CHANGE: "credits": 3
                    new_data = pd.DataFrame([{"username": new_u, "password": new_p, "credits": 3}])
                    conn.update(worksheet="users", data=pd.concat([df, new_data], ignore_index=True))
                    st.success("User Created with 3 Credits!")
                except Exception as e:
                    st.error(f"Error: {e}")

# --- DASHBOARD (LOGGED IN) ---
else:
    with st.sidebar:
        st.success(f"👤 {st.session_state.user}")
        if st.button("Logout"):
            st.session_state.login = False
            st.rerun()

    st.title("🔐 Secure New Asset")
    
    uploaded_file = st.file_uploader("Upload File (Max 1GB)", help="Images, Audio, Video, Scripts")
    
    if uploaded_file:
        st.divider()
        c1, c2 = st.columns([1, 2])
        with c1:
            st.metric("File Size", f"{uploaded_file.size / 1024:.1f} KB")
        
        with c2:
            if st.button("🛡️ SECURE & CERTIFY", type="primary", use_container_width=True):
                
                # --- CREDIT CHECK LOGIC ---
                allow_upload = False
                
                # 1. Founder is always allowed
                if st.session_state.user == "founder@creatorshield.in":
                    allow_upload = True
                
                # 2. Check Database for regular users
                elif db_active:
                    try:
                        df = conn.read(worksheet="users", ttl=0)
                        user_row = df[df['username'] == st.session_state.user]
                        
                        if not user_row.empty:
                            credits = user_row.iloc[0]['credits']
                            
                            # Check if Unlimited or > 0
                            if str(credits).lower() == "unlimited" or (isinstance(credits, (int, float)) and credits > 0):
                                allow_upload = True
                                
                                # Deduct Credit (if not unlimited)
                                if str(credits).lower() != "unlimited":
                                    # Update the specific cell
                                    idx = user_row.index[0]
                                    df.at[idx, 'credits'] = credits - 1
                                    conn.update(worksheet="users", data=df)
                            else:
                                st.error("❌ Limit Reached (3/3). Please Upgrade.")
                        else:
                            st.error("User record not found.")
                    except Exception as e:
                        st.error(f"Credit Check Error: {e}")
                
                # --- EXECUTE IF ALLOWED ---
                if allow_upload:
                    # 1. PROCESS (IST TIME)
                    ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
                    timestamp = ist_time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                    
                    # 2. DISPLAY
                    st.success(f"✅ Secured at {timestamp}")
                    st.code(file_hash, language="text")
                    
                    # 3. CLOUD SAVE
                    if db_active:
                        try:
                            v_df = conn.read(worksheet="vault", ttl=0)
                            entry = pd.DataFrame([{
                                "username": st.session_state.user,
                                "filename": uploaded_file.name,
                                "hash": file_hash,
                                "timestamp": timestamp
                            }])
                            conn.update(worksheet="vault", data=pd.concat([v_df, entry], ignore_index=True))
                        except:
                            pass 

                    st.info("ℹ️ Policy: We practice strict Data Minimization. Your file is processed in memory and immediately deleted. We do not retain copies.")

                    # 4. CERTIFICATE
                    pdf_bytes = generate_certificate(st.session_state.user, uploaded_file.name, file_hash, timestamp)
                    
                    st.download_button(
                        label="📄 Download Official Certificate (PDF)",
                        data=pdf_bytes,
                        file_name=f"Certificate_{uploaded_file.name}.pdf",
                        mime="application/pdf",
                        type="secondary"
                    )
