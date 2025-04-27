import joblib
from feature_extractor import extract_features

# Load the saved model
model = joblib.load("phishing_detector_model.pkl")

# Input URL to check
url = input("Enter URL to check: ")

# Extract features
features = extract_features(url)

# Predict
prediction = model.predict([features])

# Show result
print("Result:", "Phishing ⚠️" if prediction[0] == 1 else "Legitimate ✅")
