import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import ipaddress
import numpy as np
import geoip2.database
from datetime import datetime
import sqlite3
import os
import hashlib

# --- Database Functions ---
def init_db():
    """Initialize the SQLite database with admin and user credentials tables."""
    # Create database directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect('data/ip_app.db') # Changed Database Name
    cursor = conn.cursor()
    
    # Create admin credentials table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin_credentials (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )
    ''')
    
    # Check if admin user exists, if not create default
    cursor.execute("SELECT * FROM admin_credentials WHERE username = ?", (ADMIN_USERNAME,))
    if cursor.fetchone() is None:
        # Hash the password
        password_hash = hashlib.sha256("password".encode()).hexdigest()
        cursor.execute("INSERT INTO admin_credentials VALUES (?, ?)", (ADMIN_USERNAME, password_hash))
        conn.commit()

    # Create user credentials table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_credentials (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'  -- Added role: 'admin' or 'user'
    )
    ''')
    conn.commit()
    conn.close()

def verify_password(username, password, table='admin_credentials'):
    """Verify if username and password match the stored credentials."""
    conn = sqlite3.connect('data/ip_app.db') # Changed Database Name
    cursor = conn.cursor()
    
    # Get stored password hash
    cursor.execute(f"SELECT password_hash FROM {table} WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_hash = result[0]
        # Hash the entered password and compare
        entered_hash = hashlib.sha256(password.encode()).hexdigest()
        return stored_hash == entered_hash
    
    return False

def update_password(username, new_password, table='admin_credentials'):
    """Update the stored password for a user."""
    conn = sqlite3.connect('data/ip_app.db') # Changed Database Name
    cursor = conn.cursor()
    
    # Hash the new password
    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    # Update the password
    cursor.execute(f"UPDATE {table} SET password_hash = ? WHERE username = ?",  (password_hash, username))
    conn.commit()
    conn.close()

def create_user(username, password, role='user'):
    """Create a new user with the given username and password."""
    conn = sqlite3.connect('data/ip_app.db') # Changed Database Name
    cursor = conn.cursor()
    
    # Check if the username already exists
    cursor.execute("SELECT * FROM user_credentials WHERE username = ?", (username,))
    if cursor.fetchone() is not None:
        conn.close()
        return False, "Username already exists"
    
    # Hash the password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Insert the new user into the database
    cursor.execute("INSERT INTO user_credentials VALUES (?, ?, ?)", (username, password_hash, role))
    conn.commit()
    conn.close()
    return True, None

def get_all_users():
    """Get all users from the database."""
    conn = sqlite3.connect('data/ip_app.db') #chnaged
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM user_credentials")
    users = cursor.fetchall()
    conn.close()
    return users

def delete_user(username):
    """Delete a user from the database."""
    conn = sqlite3.connect('data/ip_app.db')  # Changed Database Name
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_credentials WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def get_user_role(username, table='user_credentials'):
    """Get the role of a user from the database."""
    conn = sqlite3.connect('data/ip_app.db')
    cursor = conn.cursor()
    
    if table == 'admin_credentials':
        return 'admin'  # Admin table users always have admin role
    
    cursor.execute("SELECT role FROM user_credentials WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return result[0]
    return None

# --- Constants ---
ADMIN_USERNAME = "admin"  # Replace with your desired username

# --- Initialize Database ---
init_db()

# --- Initialize Session State Variables ---
if 'password_entered' not in st.session_state:
    st.session_state['password_entered'] = False
if 'user_created' not in st.session_state:
    st.session_state['user_created'] = False
if 'login_table' not in st.session_state:
    st.session_state['login_table'] = 'admin_credentials'
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None

def logout():
    """Logout the user by resetting password_entered state"""
    st.session_state['password_entered'] = False
    st.session_state['login_table'] = 'admin_credentials'  # Reset to admin table
    st.session_state['username'] = None
    st.session_state['user_role'] = None

def check_password():
    """Returns True if the password is correct."""
    if not st.session_state['password_entered']:
        with st.form("login_form"):
            # Add a radio button to select login type
            login_type = st.radio("Login as:", ["Admin", "User"])
            
            # Set the table based on login type
            st.session_state['login_table'] = 'admin_credentials' if login_type == "Admin" else 'user_credentials'
            
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit_button = st.form_submit_button("Login")
            
            if submit_button:
                # Use the selected table for verification
                table = st.session_state['login_table']
                if verify_password(username, password, table):
                    st.session_state['password_entered'] = True
                    st.session_state['username'] = username
                    
                    # Store the user role in session state
                    if table == 'admin_credentials':
                        st.session_state['user_role'] = 'admin'
                    else:
                        # For user_credentials table, get the actual role from the database
                        st.session_state['user_role'] = get_user_role(username, table)
                    
                    return True
                else:
                    st.error("Incorrect username or password")
                    return False
        return False
    else:
        return True

def change_admin_password(current_password, new_password, confirm_password):
    """Changes the admin password if the current password is correct and new passwords match."""
    if verify_password(ADMIN_USERNAME, current_password):
        if new_password == confirm_password and new_password != "":
            # Update the password in the database
            update_password(ADMIN_USERNAME, new_password)
            # Display success message
            st.success(f"Password changed successfully!")
            return True
        else:
            st.error("New passwords do not match or password is empty.")
            return False
    else:
        st.error("Incorrect current password.")
        return False

# --- Main Application ---
st.set_page_config(page_title="IP Geolocation App", layout="wide")

# Custom CSS for futuristic look
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: rgba(7, 25, 43, 0.4);
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(14, 78, 130, 0.8) !important;
    }
    h1, h2, h3 {
        color: #4dd0e1;
    }
    .stDataFrame {
        border: 1px solid #2c3a47;
        border-radius: 5px;
    }
    input {
        border: 1px solid #00ffff !important;
        border-radius: 8px !important;
        background-color: #121212 !important;
        color: #00ffff !important;
    }
    button[kind="primary"] {
        background-color: #00ffff !important;
        color: black !important;
        border-radius: 8px !important;
        font-weight: bold !important;
        box-shadow: 0px 0px 10px #00ffff;
        transition: all 0.3s ease-in-out;
    }
    button[kind="primary"]:hover {
        background-color: #0ff !important;
        box-shadow: 0px 0px 20px #0ff;
        transform: scale(1.02);
    }
    .stMetric {
        background: #1e1e1e;
        border-radius: 15px;
        padding: 1rem;
        box-shadow: 0 0 10px #00ffff33;
    }
</style>
""", unsafe_allow_html=True)

st.title("🌍 IP Geolocation Dashboard & Prediction")

if check_password():
    # Display user info
    st.sidebar.info(f"Logged in as: {st.session_state['username']} ({st.session_state['user_role']})")
    
    # Only show admin settings to admin users
    if st.session_state['user_role'] == 'admin':
        with st.expander("⚙️ Admin Settings"):
            st.subheader("Change Password")
            
            # Use a form for password change
            with st.form("password_change_form"):
                current_password = st.text_input("Current Password", type="password", key="current_pwd")
                new_password = st.text_input("New Password", type="password", key="new_pwd")  
                confirm_password = st.text_input("Confirm New Password", type="password", key="confirm_pwd")
                pwd_submit = st.form_submit_button("Change Password")
            
            if pwd_submit:
                if change_admin_password(current_password, new_password, confirm_password):
                    # Rerun the app to ensure changes take effect
                    st.rerun()
            
            # --- User Management ---
            st.subheader("User Management")
            
            # Create User Form
            with st.form("create_user_form"):
                new_username = st.text_input("New Username")
                new_password = st.text_input("New Password", type="password")
                new_role = st.selectbox("Role", ["user", "admin"])
                create_user_button = st.form_submit_button("Create User")
                
            if create_user_button:
                success, message = create_user(new_username, new_password, new_role)
                if success:
                    st.success(f"User {new_username} created successfully with role: {new_role}")
                    st.session_state['user_created'] = True # Set a session state variable
                else:
                    st.error(message)

            # Display User List
            st.subheader("User List")
            users = get_all_users()
            if users:
                user_df = pd.DataFrame(users, columns=["Username", "Role"])
                st.dataframe(user_df)

                # Add a delete button for each user
                for user in users:
                    if st.button(f"Delete {user[0]}", key=f"delete_{user[0]}"):
                        delete_user(user[0])
                        st.warning(f"User {user[0]} deleted!")
                        st.rerun()  # Refresh the page to update the user list
            else:
                st.info("No users found.")

    # Add logout button in sidebar
    if st.sidebar.button("Logout"):
        logout()
        st.rerun()

    # --- Dashboard Content (Conditional Rendering) ---
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🧠 Predict Login Familiarity", "🔒 Login Familiarity AI"])

    # ───────────────────────────
    # 📊 TAB 1: Dashboard Section
    # ───────────────────────────
    with tab1:
        st.header("Geolocation Dashboard")
        uploaded_file = st.file_uploader("Upload the geolocation_results.csv file", type=["csv"], key="dashboard")

        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)

            # Display data with styling
            st.subheader("📋 Raw Data")
            st.dataframe(df, height=300)

            col1, col2 = st.columns(2)

            # Country-wise IP count with futuristic styling
            if "Country" in df.columns:
                with col1:
                    st.subheader("📊 IP Distribution by Country")
                    country_count = df["Country"].value_counts().reset_index()
                    country_count.columns = ["Country", "IP Count"]

                    # Create a more futuristic bar chart
                    fig = go.Figure()
                    fig.add_trace(go.Bar(
                        x=country_count["Country"],
                        y=country_count["IP Count"],
                        marker=dict(
                            color=country_count["IP Count"],
                            colorscale='Plasma',
                            line=dict(width=1, color='rgba(50, 171, 96, 0.7)')
                        ),
                        text=country_count["IP Count"],
                        textposition='outside',
                        hoverinfo='text',
                        hovertext=[f"{country}: {count} IPs" for country, count in
                                    zip(country_count["Country"], country_count["IP Count"])]
                    ))

                    fig.update_layout(
                        plot_bgcolor='rgba(17, 17, 31, 0.9)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#4dd0e1'),
                        height=400,
                        margin=dict(t=50, b=50, l=20, r=20),
                        xaxis=dict(
                            showgrid=False,
                            zeroline=False,
                            showline=True,
                            linecolor='rgba(255, 255, 255, 0.2)'
                        ),
                        yaxis=dict(
                            showgrid=True,
                            gridcolor='rgba(255, 255, 255, 0.1)',
                            zeroline=False
                        )
                    )

                    st.plotly_chart(fig, use_container_width=True)

                # IP visualization on world map
                with col2:
                    st.subheader("🗺️ IP Locations Worldwide")
                    # Create a map of IP locations
                    if "Country" in df.columns:
                        # Get unique countries with counts
                        country_data = df["Country"].value_counts().reset_index()
                        country_data.columns = ["Country", "Count"]

                        # Create a choropleth map
                        fig = px.choropleth(
                            country_data,
                            locations="Country",
                            locationmode="country names",
                            color="Count",
                            hover_name="Country",
                            color_continuous_scale=px.colors.sequential.Plasma,
                            projection="natural earth",
                            title="Global IP Distribution"
                        )

                        fig.update_layout(
                            geo=dict(
                                showland=True,
                                landcolor="rgba(17, 17, 31, 0.4)",
                                showocean=True,
                                oceancolor="rgba(7, 25, 43, 0.7)",
                                showlakes=False,
                                showcountries=True,
                                countrycolor="rgba(255, 255, 255, 0.3)",
                                projection_type="natural earth",
                                showframe=False
                            ),
                            plot_bgcolor='rgba(0,0,0,0)',
                            paper_bgcolor='rgba(0,0,0,0)',
                            font=dict(color='#4dd0e1'),
                            height=400,
                            margin=dict(t=50, b=50, l=20, r=20),
                        )

                        st.plotly_chart(fig, use_container_width=True)

            # IP Class Distribution
            st.subheader("📱 IP Classification Analysis")
            col1, col2 = st.columns(2)

            with col1:
                # Function to classify IP
                def classify_ip(ip):
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            return "Private"
                        elif ip_obj.is_global:
                            return "Public"
                        elif ip_obj.is_loopback:
                            return "Loopback"
                        else:
                            return "Other"
                    except:
                        return "Invalid"

                # Add IP classification
                df["IP_Class"] = df["IP"].apply(classify_ip)

                # Create IP classification chart
                ip_class_data = df["IP_Class"].value_counts().reset_index()
                ip_class_data.columns = ["Class", "Count"]

                fig = go.Figure(data=[
                    go.Pie(
                        labels=ip_class_data["Class"],
                        values=ip_class_data["Count"],
                        hole=.7,
                        marker=dict(
                            colors=px.colors.sequential.Plasma,
                            line=dict(color='rgba(0,0,0,0)', width=1)
                        ),
                        textinfo='label+percent',
                        insidetextorientation='radial'
                    )
                ])

                fig.update_layout(
                    title_text="IP Classification",
                    annotations=[dict(text="IP Types", x=0.5, y=0.5, font_size=15, font_color='#4dd0e1', showarrow=False)],
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#4dd0e1'),
                    showlegend=False
                )

                st.plotly_chart(fig, use_container_width=True)

            with col2:
                # Create IP network distribution
                def get_network(ip):
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.version == 4:
                            # Get first octet for class
                            octet = int(str(ip_obj).split('.')[0])
                            if octet < 128:
                                return "Class A"
                            elif octet < 192:
                                return "Class B"
                            elif octet < 224:
                                return "Class C"
                            elif octet < 240:
                                return "Class D (Multicast)"
                            else:
                                return "Class E (Reserved)"
                        else:
                            return "IPv6"
                    except:
                        return "Invalid"

                df["Network_Class"] = df["IP"].apply(get_network)
                network_data = df["Network_Class"].value_counts().reset_index()
                network_data.columns = ["Network Class", "Count"]

                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=network_data["Network Class"],
                    y=network_data["Count"],
                    marker=dict(
                        color=network_data["Count"],
                        colorscale='Plasma',
                        line=dict(width=1, color='rgba(50, 171, 96, 0.7)')
                    ),
                    text=network_data["Count"],
                    textposition='outside'
                ))

                fig.update_layout(
                    title_text="IP Network Classes",
                    plot_bgcolor='rgba(17, 17, 31, 0.9)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#4dd0e1'),
                    margin=dict(t=70, b=50, l=20, r=20),
                    xaxis=dict(
                        showgrid=False,
                        zeroline=False,
                        showline=True,
                        linecolor='rgba(255, 255, 255, 0.2)'
                    ),
                    yaxis=dict(
                        showgrid=True,
                        gridcolor='rgba(255, 255, 255, 0.1)',
                        zeroline=False
                    )
                )

                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Please upload the geolocation_results.csv file to see the dashboard.")

    # ───────────────────────────
    # 🧠 TAB 2: Prediction Section
    # ───────────────────────────
    with tab2:
        st.header("Predict Login Location Familiarity")
        st.subheader("Step 1: Upload Historical Geolocation Data")
        past_file = st.file_uploader("Upload past geolocation_results.csv file", type=["csv"], key="past")

        # IP subnet similarity calculation function
        def calculate_ip_similarity(ip1, ip2):
            try:
                # Convert to IP objects
                ip_obj1 = ipaddress.ip_address(ip1)
                ip_obj2 = ipaddress.ip_address(ip2)

                # Check if they're in the same /24 subnet (share first 3 octets)
                if ip_obj1.version == ip_obj2.version:  # Same IP version
                    if ip_obj1.version == 4:  # IPv4
                        # Check first 3 octets match
                        return 1.0 if str(ip_obj1).rsplit('.', 1)[0] == str(ip_obj2).rsplit('.', 1)[0] else 0.0
                    else:  # IPv6 - simplified for demo
                        # Check first 6 segments match (out of 8)
                        return 1.0 if str(ip_obj1).split(':')[:6] == str(ip_obj2).split(':')[:6] else 0.0
                return 0.0
            except:
                return 0.0

        # Function to calculate risk score based on IP 
        def calculate_risk_score_ip(ip, known_ips):
            # Initialize base risk score (0-100, where 0 is lowest risk)
            risk_score = 50  # Start at medium risk

            # 1. Exact IP match (lowest risk)
            if ip in known_ips:
                risk_score -= 40  # Significant reduction in risk
            else:
                # 2. IP similarity to known IPs (subnet analysis)
                max_similarity = 0
                for known_ip in known_ips:
                    similarity = calculate_ip_similarity(ip, known_ip)
                    max_similarity = max(max_similarity, similarity)

                # Adjust score based on IP similarity
                if max_similarity >= 0.9:  # Very similar IP
                    risk_score -= 30
                elif max_similarity >= 0.5:  # Somewhat similar IP
                    risk_score -= 15

            # Ensure risk score stays within bounds
            return max(0, min(100, risk_score))

        if past_file:
            past_df = pd.read_csv(past_file)
            required_columns = ["IP"]  # Changed to only require IP

            if all(col in past_df.columns for col in required_columns):
                # Extract known IPs
                known_ips = set(past_df["IP"].tolist())

                st.success(f"✅ Loaded {len(past_df)} historical records with {len(known_ips)} unique IPs")

                st.subheader("Step 2: Upload New Login Attempts")
                new_file = st.file_uploader("Upload new logins CSV with IP column", type=["csv"], key="new") #changed

                if new_file:
                    new_df = pd.read_csv(new_file)
                    if all(col in new_df.columns for col in required_columns):
                        # Calculate prediction results
                        results = []
                        for _, row in new_df.iterrows():
                            ip = row["IP"]
                            
                            # Calculate risk score
                            risk_score = calculate_risk_score_ip(ip, known_ips)

                            # Determine risk level
                            if risk_score < 20:
                                risk_level = "🟢 Low Risk"
                            elif risk_score < 60:
                                risk_level = "🟡 Medium Risk"
                            else:
                                risk_level = "🔴 High Risk"

                            # Find similar IPs for suspicious logins
                            similar_ips = []
                            if risk_score >= 60: # High Risk Only
                                for known_ip in known_ips:
                                    similarity = calculate_ip_similarity(ip, known_ip)
                                    if similarity > 0:
                                        similar_ips.append(known_ip)
                                similar_ips = similar_ips[:3]  # Limit to top 3

                            results.append({
                                "IP": ip,
                                "Risk Score": risk_score,
                                "Risk Level": risk_level,
                                "Similar Known IPs": ", ".join(similar_ips) if similar_ips else "None"
                            })

                        if results:
                            results_df = pd.DataFrame(results)
                            st.subheader("Prediction Results")
                            st.dataframe(results_df)
                    else:
                        st.error("New logins CSV must contain 'IP' column.") #changed
            else:
                st.error("Past geolocation CSV must contain 'IP' column.") #changed
                
    # ───────────────────────────
    # 🔒 TAB 3: Login Familiarity AI
    # ───────────────────────────
    with tab3:
        # Function to calculate risk score based on familiarity
        def calculate_risk_score(ip, country, region, known_ips, known_locations, time_now):
            risk = 0
            if ip not in known_ips:
                risk += 40
            if (country.lower(), region.lower()) not in known_locations:
                risk += 40
            hour = time_now.hour
            if hour < 6 or hour > 22:
                risk += 20
            return risk

        with st.container():
            st.markdown(
                """
                <h3 style='color: #00ffea; font-weight: 600; margin-bottom: 20px;'>🧠 Login Familiarity AI</h3>
                <p style='color: #ccc; font-size: 14px;'>Enter login details to evaluate how familiar this login attempt is based on historical user data.</p>
                """,
                unsafe_allow_html=True
            )
            past_file = st.file_uploader("📁 Upload Past Login CSV File", type=["csv"], key="past_logins")
            new_ip = st.text_input("🌐 IP Address", value="192.168.1.45")
            new_country = st.text_input("🗺️ Country", value="India")
            new_region = st.text_input("🏞️ Region / State", value="Tamil Nadu")
            new_timestamp = st.text_input("⏱️ Timestamp (YYYY-MM-DD HH:MM:SS)", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            predict_button = st.button("🧬 Predict Familiarity", use_container_width=True)
            
            if predict_button:
                try:
                    new_time = datetime.strptime(new_timestamp, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    st.error("❌ Invalid timestamp format. Please use YYYY-MM-DD HH:MM:SS")
                    new_time = None
                    
                if past_file is not None and new_time:
                    past_df = pd.read_csv(past_file)
                    known_ips = past_df["IP"].dropna().unique().tolist()
                    
                    # Fixed the syntax error in the original code
                    known_locations = set([
                        (str(row["Country"]).lower(), str(row["Region"]).lower())
                        for _, row in past_df.iterrows()
                        if pd.notna(row["Country"]) and pd.notna(row["Region"])
                    ])
                    
                    risk = calculate_risk_score(new_ip, new_country, new_region, known_ips, known_locations, time_now=new_time)
                    st.markdown("<hr style='margin: 20px 0;'>", unsafe_allow_html=True)
                    st.metric(label="🛡️ Risk Score (0=Safe, 100=Risky)", value=int(risk))
                    
                    if risk < 30:
                        st.success("✅ This login seems familiar and safe.")
                    elif risk < 60:
                        st.warning("⚠️ This login is moderately risky.")
                    else:
                        st.error("🚨 This login appears unfamiliar or risky.")