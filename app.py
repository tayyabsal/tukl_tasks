import os

import fitz  # PyMuPDF
import joblib
from flask import Flask, jsonify, render_template, request
from PyPDF2 import PdfFileReader

# Initialize Flask app
app = Flask(__name__)

# Load the trained model
model = joblib.load('random_forest_model.joblib')  # Make sure this path is correct

# Define the feature flags for feature extraction
feature_flags = [
    'pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters',
    'isEncrypted', 'embedded files', 'images', 'text', 'obj', 'endobj',
    'stream', 'endstream', 'xref', 'trailer', 'startxref', 'pageno',
    'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform',
    'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'Colors'
]

# Function to extract features from PDF
def extract_pdf_features(pdf_path):
    features = {}
    # Initialize all features to zero
    for flag in feature_flags:
        features[flag] = 0
    
    doc = fitz.open(pdf_path)
    
    # Extract PDF size
    features['pdfsize'] = os.path.getsize(pdf_path)
    
    # Extract metadata
    metadata = doc.metadata
    features['metadata size'] = len(str(metadata))
    
    # Extract number of pages
    features['pages'] = doc.page_count
    
    # Extract title length
    features['title characters'] = len(metadata.get('title', ''))
    
    # Check if the PDF is encrypted
    features['isEncrypted'] = 1 if doc.is_encrypted else 0
    
    # Check if the PDF has embedded files
    try:
        with open(pdf_path, "rb") as file:
            reader = PdfFileReader(file)
            if '/EmbeddedFiles' in reader.trailer['/Root']:
                features['embedded files'] = 1
    except Exception as e:
        print(f"Error checking embedded files: {e}")
    
    # Extract text and image counts
    text_count = 0
    image_count = 0
    for page in doc:
        text_count += len(page.get_text("text"))
        image_count += len(page.get_images(full=True))
    
    features['text'] = text_count
    features['images'] = image_count
    
    # Check for keywords in the PDF text (this can be adjusted to your needs)
    feature_keywords = [
        'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
        'pageno', 'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction',
        'Acroform', 'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'Colors'
    ]
    
    for keyword in feature_keywords:
        features[keyword] = sum([1 for page in doc if keyword in page.get_text('text')])
    
    return features

# Function to predict malicious or benign
def predict_malicious_or_benign(pdf_path):
    features = extract_pdf_features(pdf_path)
    # Ensure the feature vector has exactly 30 features
    feature_list = [features.get(flag, 0) for flag in feature_flags]
    prediction = model.predict([feature_list])
    return prediction[0]

# Flask route to upload PDF and get prediction
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        
        if file and file.filename.endswith('.pdf'):
            # Save the file temporarily
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)
            
            # Predict if the PDF is malicious or benign
            result = predict_malicious_or_benign(file_path)
            
            # Clean up the uploaded file
            os.remove(file_path)
            
            # Return the result
            if result == 1:
                return render_template('index.html', message="Malicious PDF detected.")
            else:
                return render_template('index.html', message="Benign PDF detected.")
    
    return render_template('index.html', message="Upload a PDF to check.")

if __name__ == '__main__':
    app.run(debug=True)
