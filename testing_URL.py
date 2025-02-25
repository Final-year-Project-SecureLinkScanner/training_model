import joblib
import pandas as pd
import numpy as np
import os

# Load trained model
model = joblib.load("xgboost_model_adv.pkl")

# Get expected features from the trained model and convert them to a list
expected_features = list(model.feature_names_in_)

# Define paths for logs
FEATURES_FILE = "extracted_features.csv"
RESULTS_FILE = "predictions_log.txt"

def extract_features_from_url(url):
    """Extract structured numerical features from URL and ensure compatibility with trained model."""

    features = {
        "NumDots": url.count('.'),
        "SubdomainLevel": url.count('.') - 1,
        "PathLevel": url.count('/'),
        "NumDash": url.count('-'),
        "NumDashInHostname": url.split('/')[0].count('-'),
        "HostnameLength": len(url.split('/')[0]),
        "PathLength": len(url.split('/')) - 1,
        "UrlLength": len(url),
        "AtSymbol": 1 if "@" in url else 0,
        "TildeSymbol": 1 if "~" in url else 0,
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": url.count('?'),
        "NumAmpersand": url.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": 1 if not url.startswith("https") else 0,
        "RandomString": 1 if any(c.isdigit() for c in url) and any(c.isalpha() for c in url) else 0,
        "IpAddress": 1 if any(c.isdigit() for c in url.split('/')[0]) else 0,
        "DomainInSubdomains": 1 if "example" in url else 0,
        "DomainInPaths": 1 if "example" in url.split('/')[-1] else 0,
        "HttpsInHostname": 1 if "https" in url.split('/')[0] else 0,
        "QueryLength": len(url.split('?')[-1]) if '?' in url else 0,
        "DoubleSlashInPath": 1 if "//" in url.split('/')[1:] else 0,
        "NumSensitiveWords": sum(word in url.lower() for word in ["login", "bank", "verify", "secure"]),
        "EmbeddedBrandName": 1 if "paypal" in url.lower() else 0,
        "PctExtHyperlinks": 0.5,
        "PctExtResourceUrls": 0.3,
        "ExtFavicon": 1 if "favicon.ico" in url else 0,
        "InsecureForms": 1 if "http" in url and "form" in url.lower() else 0,
        "RelativeFormAction": 0,
        "ExtFormAction": 0,
        "AbnormalFormAction": 0,
        "PctNullSelfRedirectHyperlinks": 0.2,
        "FrequentDomainNameMismatch": 0,
        "FakeLinkInStatusBar": 0,
        "RightClickDisabled": 0,
        "PopUpWindow": 0,
        "SubmitInfoToEmail": 0,
        "IframeOrFrame": 0,
        "MissingTitle": 0,
        "ImagesOnlyInForm": 0,
        "SubdomainLevelRT": url.count('.') - 1,
        "UrlLengthRT": len(url),
        "PctExtResourceUrlsRT": 0.3,
        "AbnormalExtFormActionR": 0,
        "ExtMetaScriptLinkRT": 0,
        "PctExtNullSelfRedirectHyperlinksRT": 0.2
    }

    # Convert extracted features to a DataFrame
    df = pd.DataFrame([features])

    # 🔹 Debugging: Print feature dictionary before alignment
    print("\n🔍 Raw Extracted Features Dictionary:")
    print(features)

    # 🔹 Debugging: Check DataFrame before modifying it
    print("\n🔍 DataFrame BEFORE reordering:")
    print(df.head())

    # 🔹 Debugging: Ensure expected features are correct
    print("\n🔍 Expected Features from Model:")
    print(expected_features)

    # Ensure all required features exist and keep extracted values intact
    df = df.reindex(columns=expected_features, fill_value=0)

    # 🔹 Debugging: Print DataFrame after reordering
    print("\n✅ DataFrame AFTER reordering (should retain original values, not all zeros):")
    print(df.head())

    return df

def predict_url(url):
    """Predict phishing status, log results, and save extracted features."""
    features = extract_features_from_url(url)

    # Print extracted features
    print(f"\nExtracted Features for: {url}")
    print(features)

    # Save extracted features to CSV file
    if os.path.exists(FEATURES_FILE):
        features.to_csv(FEATURES_FILE, mode='a', header=False, index=False)
    else:
        features.to_csv(FEATURES_FILE, mode='w', header=True, index=False)

    # Make prediction
    prediction = model.predict(features)
    result = "Phishing" if prediction[0] == 1 else "Legitimate"

    # Log result to a file
    with open(RESULTS_FILE, "a") as f:
        f.write(f"URL: {url} --> Prediction: {result}\n")

    return result

# List of hardcoded URLs to check
test_urls = [
    "http://example.com/free-money",
    "https://www.google.com",
    "https://customs-ie.com/ie/schedule",
    "https://customscharge-tracking-delivery.com/",
    "https://Anpost-parcelredirect.com",
    "https://customs-ie.com/ie/schedule",
    "www.customs.ie-charge.info"
]

# Run predictions on all test URLs
for url in test_urls:
    print(f"Checking: {url}")
    print(predict_url(url))

# Notify where results are saved
print(f"\nExtracted features saved to: {FEATURES_FILE}")
print(f"Prediction results saved to: {RESULTS_FILE}")
