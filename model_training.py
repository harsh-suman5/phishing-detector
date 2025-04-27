import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Assume you have a dataset already:
# For now, let's create a dummy dataset
data = {
    'url': [
        "http://192.168.1.1/login",
        "https://www.bankofamerica.com",
        "http://phishing-site-login.com",
        "https://secure.apple.com/account",
    ],
    'label': [1, 0, 1, 0]  # 1 = Phishing, 0 = Legitimate
}

df = pd.DataFrame(data)

# Feature extraction
def extract_features(url):
    # Example feature extraction logic
    return [
        url.startswith("http://"),  # is_ip
        url.count('.') - 1,         # subdomains
        '@' in url,                 # has_at
        '-' in url,                 # has_hyphen
        url.startswith("https://"), # uses_https
        url.count('//') - 1,        # count_double_slash
        len(url),                   # url_length
        any(word in url for word in ["login", "secure", "account"]),  # suspicious_words
        0                           # domain_age (placeholder)
    ]

feature_list = []
for url in df['url']:
    feature_list.append(extract_features(url))

X = pd.DataFrame(feature_list, columns=[
    'is_ip', 'subdomains', 'has_at', 'has_hyphen', 
    'uses_https', 'count_double_slash', 'url_length', 
    'suspicious_words', 'domain_age'
])

y = df['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "phishing_detector_model.pkl")
print("Model saved as phishing_detector_model.pkl")
