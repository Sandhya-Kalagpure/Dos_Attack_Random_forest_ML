import streamlit as st
import numpy as np
import pickle
import socket
import struct

# Load the machine learning model
model = pickle.load(open("rf_model.pkl", "rb"))

# Function to convert IPv4 to numeric
def ipv4_to_numeric(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        st.write(f"Error converting IP addres: {ip}")
        return 0
    
    
# Define a function to convert input strings to floats
def get_float_input(prompt):
    value = st.text_input(prompt)
    if value == "":
        return 0.0  # Use 0.0 as default for missing values
    return float(value)


# Define the input fields
st.title("Dos Attack Prediction App")
st.header("Enter the following log file attributes:")

# Define a function to convert input strings to floats
def get_float_input(prompt):
    value = st.text_input(prompt)
    if value == "":
        return 0.0  # Use 0.0 as default for missing values
    return float(value)

background_image = "img.jpg"

# Apply custom CSS for background image
st.markdown(
    f"""
    <style>
    .reportview-container {{
        background: url({background_image});
        background-size: cover;
    }}
    </style>
    """,
    unsafe_allow_html=True
)

# Get IP input and convert to numeric
IPV4_SRC_ADDR = st.text_input("IPV4_SRC_ADDR")
IPV4_DST_ADDR = st.text_input("IPV4_DST_ADDR")
IPV4_SRC_ADDR_NUMERIC = ipv4_to_numeric(IPV4_SRC_ADDR)
IPV4_DST_ADDR_NUMERIC = ipv4_to_numeric(IPV4_DST_ADDR)

L4_SRC_PORT = get_float_input("L4_SRC_PORT")
L4_DST_PORT = get_float_input("L4_DST_PORT")
PROTOCOL = get_float_input("PROTOCOL")
L7_PROTO = get_float_input("L7_PROTO")
IN_BYTES = get_float_input("IN_BYTES")
IN_PKTS = get_float_input("IN_PKTS")
OUT_BYTES = get_float_input("OUT_BYTES")
OUT_PKTS = get_float_input("OUT_PKTS")
TCP_FLAGS = get_float_input("TCP_FLAGS")
CLIENT_TCP_FLAGS = get_float_input("CLIENT_TCP_FLAGS")
SERVER_TCP_FLAGS = get_float_input("SERVER_TCP_FLAGS")
FLOW_DURATION_MILLISECONDS = get_float_input("FLOW_DURATION_MILLISECONDS")
DURATION_IN = get_float_input("DURATION_IN")
DURATION_OUT = get_float_input("DURATION_OUT")
MIN_TTL = get_float_input("MIN_TTL")
NUM_PKTS_UP_TO_128_BYTES = get_float_input("NUM_PKTS_UP_TO_128_BYTES")
NUM_PKTS_128_TO_256_BYTES = get_float_input("NUM_PKTS_128_TO_256_BYTES")
NUM_PKTS_256_TO_512_BYTES = get_float_input("NUM_PKTS_256_TO_512_BYTES")
NUM_PKTS_512_TO_1024_BYTES = get_float_input("NUM_PKTS_512_TO_1024_BYTES")
NUM_PKTS_1024_TO_1514_BYTES = get_float_input("NUM_PKTS_1024_TO_1514_BYTES")
TCP_WIN_MAX_IN = get_float_input("TCP_WIN_MAX_IN")
TCP_WIN_MAX_OUT = get_float_input("TCP_WIN_MAX_OUT")
Dataset = get_float_input("Dataset")

# Add a "Predict" button
predict_button = st.button("Predict")

# Make the prediction when the button is clicked
if predict_button:
    input_data = [
        IPV4_SRC_ADDR_NUMERIC, IPV4_DST_ADDR_NUMERIC, L4_SRC_PORT, L4_DST_PORT, 
        PROTOCOL, L7_PROTO, IN_BYTES, IN_PKTS, OUT_BYTES, OUT_PKTS, TCP_FLAGS, 
        CLIENT_TCP_FLAGS, SERVER_TCP_FLAGS, FLOW_DURATION_MILLISECONDS, DURATION_IN, 
        DURATION_OUT, MIN_TTL, NUM_PKTS_UP_TO_128_BYTES, NUM_PKTS_128_TO_256_BYTES, 
        NUM_PKTS_256_TO_512_BYTES, NUM_PKTS_512_TO_1024_BYTES, NUM_PKTS_1024_TO_1514_BYTES, 
        TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT, Dataset
    ]

    input_data_2d = np.array(input_data).reshape(1, -1)

    prediction = model.predict(input_data_2d)

    # Display the prediction
    if prediction == 1:
        st.write("The attack is a DoS attack.")
    else:
        st.write("The attack is not a DoS attack.")






