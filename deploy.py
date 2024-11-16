import streamlit as st
import os
import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder
from scipy import stats

# Load the trained models 
random_forest_model = joblib.load(os.path.join("model", "random_forest.pkl"))
gradient_boosting_model = joblib.load(os.path.join("model", "gradient_boosting.pkl"))
decision_tree_model = joblib.load(os.path.join("model",'decision_tree.pkl'))
naive_bayes_model = joblib.load(os.path.join("model",'naive_bayes.pkl'))

# Set up the Streamlit app layout
st.title("Intrusion Detection System Prediction")
st.write("Select the model and input features to get predictions.")

# Dropdown for model selection
model_choice = st.selectbox("Select the Model", 
                             ["Random Forest", "Gradient Boosting", 
                              "Decision Tree", "Naive Bayes"])

# Input features based on KDD dataset
duration = st.number_input("Duration", value=0.0)
protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])

# Updated flag dropdown
flag = st.selectbox("Flag", ["SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "RSTOS0", "S3", "OTH"])

src_bytes = st.number_input("Source Bytes", value=0.0)
dst_bytes = st.number_input("Destination Bytes", value=0.0)
land = st.number_input("Land (0 or 1)", value=0)
wrong_fragment = st.number_input("Wrong Fragment", value=0)
urgent = st.number_input("Urgent", value=0)
hot = st.number_input("Hot", value=0)
num_failed_logins = st.number_input("Number of Failed Logins", value=0)
logged_in = st.number_input("Logged In (0 or 1)", value=0)
num_compromised = st.number_input("Number Compromised", value=0)
root_shell = st.number_input("Root Shell (0 or 1)", value=0)
su_attempted = st.number_input("SU Attempted (0 or 1)", value=0)
num_file_creations = st.number_input("Number of File Creations", value=0)
num_shells = st.number_input("Number of Shells", value=0)
num_access_files = st.number_input("Number of Access Files", value=0)
num_outbound_cmds = st.number_input("Number of Outbound Commands", value=0)
is_host_login = st.number_input("Is Host Login (0 or 1)", value=0)
count = st.number_input("Count", value=0)
serror_rate = st.number_input("Service Error Rate", value=0.0)
rerror_rate = st.number_input("Remote Error Rate", value=0.0)
same_srv_rate = st.number_input("Same Service Rate", value=0.0)
diff_srv_rate = st.number_input("Different Service Rate", value=0.0)
srv_diff_host_rate = st.number_input("Service Different Host Rate", value=0.0)
dst_host_count = st.number_input("Destination Host Count", value=0)

dst_host_diff_srv_rate = st.number_input("Destination Host Different Service Rate", value=0.0)
dst_host_same_src_port_rate = st.number_input("Destination Host Same Source Port Rate", value=0.0)
dst_host_srv_diff_host_rate = st.number_input("Destination Host Service Different Host Rate", value=0.0)

# Updated flag mapping
protocol_mapping = {"tcp": 0, "udp": 1, "icmp": 2}
flag_mapping = {
    "SF": 0, "S0": 1, "REJ": 2, "RSTR": 3, "RSTO": 4, "SH": 5, 
    "S1": 6, "S2": 7, "RSTOS0": 8, "S3": 9, "OTH": 10
}

# Convert categorical features to numeric values
protocol_type_encoded = protocol_mapping[protocol_type]
flag_encoded = flag_mapping[flag]

# Create a feature array with all required features (32 features)
features = np.array([[duration, 
                      protocol_type_encoded, 
                      flag_encoded, 
                      src_bytes, 
                      dst_bytes,
                      land, 
                      wrong_fragment, 
                      urgent, 
                      hot, 
                      num_failed_logins, 
                      logged_in, 
                      num_compromised, 
                      root_shell, 
                      su_attempted,
                      num_file_creations,
                      num_shells,
                      num_access_files,
                      num_outbound_cmds,
                      is_host_login,
                      count,
                      serror_rate,
                      rerror_rate,
                      same_srv_rate,
                      diff_srv_rate,
                      srv_diff_host_rate,
                      dst_host_count,
                      dst_host_diff_srv_rate,
                      dst_host_same_src_port_rate,
                      dst_host_srv_diff_host_rate]])

# Ensure the shape of features is correct (1 sample, 32 features)
features = features.reshape(1, -1)

# Mapping the prediction output to specific attack types from the KDD dataset
attack_types = {0: 'back._dos', 
                1: 'buffer_overflow._u2r',
                2: 'ftp_write._r2l',
                3: 'guess_passwd._r2l',
                4: 'imap._r2l',
                5: 'ipsweep._probe',
                6: 'land._dos',
                7: 'loadmodule._u2r',
                8: 'multihop._r2l',
                9: 'neptune._dos',
                10: 'nmap._probe',
                11: 'normal._normal',
                12: 'perl._u2r',
                13: 'phf._r2l',
                14: 'pod._dos',
                15: 'portsweep._probe',
                16: 'rootkit._u2r',
                17: 'satan._probe',
                18: 'smurf._dos',
                19: 'spy._r2l',
                20: 'teardrop._dos',
                21: 'warezclient._r2l',
                22: 'warezmaster._r2l'}

# Make predictions based on the selected model
if st.button("Predict"):
    try:
        # Get predictions from the selected model
        if model_choice == "Random Forest":
            model = random_forest_model
        elif model_choice == "Gradient Boosting":
            model = gradient_boosting_model
        elif model_choice == "Decision Tree":
            model = decision_tree_model
        elif model_choice == "Naive Bayes":
            model = naive_bayes_model

        # Make prediction
        prediction = model.predict(features)[0]

        # Map the prediction to the attack type
        attack_prediction = attack_types.get(prediction, 'Unknown')

        # Determine the category of the attack
        attack_category = "Normal" if prediction == 11 else "Attack"
        
        # Display the prediction result
        st.write(f"**Prediction Index:** {prediction}")
        st.write(f"**Attack Type:** {attack_prediction}")
        st.write(f"**Attack Category:** {attack_category}")

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
