#!/usr/bin/env python3
"""
Machine Learning Model Training for Intelligent WAF
Trains and manages ML models for threat detection
"""

import pandas as pd
import numpy as np
import joblib
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os
import warnings
warnings.filterwarnings('ignore')

class MLModelTrainer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.scaler = StandardScaler()
        self.feature_names = []
        
    def generate_training_data(self, num_samples=10000):
        """
        Generate synthetic training data with malicious and benign requests
        This simulates real-world HTTP request patterns
        """
        print("📊 Generating training data...")
        
        data = []
        
        # Benign requests (70% of data)
        for i in range(int(num_samples * 0.7)):
            data.append(self._generate_benign_request())
        
        # SQL Injection attacks (10%)
        for i in range(int(num_samples * 0.1)):
            data.append(self._generate_sqli_request())
        
        # XSS attacks (10%)
        for i in range(int(num_samples * 0.1)):
            data.append(self._generate_xss_request())
        
        # Path Traversal attacks (5%)
        for i in range(int(num_samples * 0.05)):
            data.append(self._generate_path_traversal_request())
        
        # Command Injection attacks (5%)
        for i in range(int(num_samples * 0.05)):
            data.append(self._generate_command_injection_request())
        
        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Save training data
        os.makedirs('data/training', exist_ok=True)
        df.to_csv('data/training/training_data.csv', index=False)
        
        print(f"✅ Generated {len(df)} training samples")
        return df
    
    def _generate_benign_request(self):
        """Generate benign HTTP request"""
        urls = [
            '/home', '/about', '/contact', '/products', '/login',
            '/api/users', '/api/data', '/images/logo.png', '/css/style.css'
        ]
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        return {
            'url': np.random.choice(urls),
            'headers': json.dumps({'User-Agent': np.random.choice(user_agents)}),
            'body': 'username=user&password=pass123',
            'label': 0  # Benign
        }
    
    def _generate_sqli_request(self):
        """Generate SQL injection attack request"""
        payloads = [
            "admin' OR '1'='1",
            "'; DROP TABLE users; --",
            "UNION SELECT username, password FROM users",
            "' OR 1=1--",
            "'; EXEC xp_cmdshell('dir')--"
        ]
        
        return {
            'url': f'/login?username={np.random.choice(payloads)}',
            'headers': '{"User-Agent": "sqlmap/1.0"}',
            'body': f'username={np.random.choice(payloads)}&password=test',
            'label': 1  # Malicious
        }
    
    def _generate_xss_request(self):
        """Generate XSS attack request"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        
        return {
            'url': f'/search?q={np.random.choice(payloads)}',
            'headers': '{"User-Agent": "Mozilla/5.0"}',
            'body': f'comment={np.random.choice(payloads)}',
            'label': 1  # Malicious
        }
    
    def _generate_path_traversal_request(self):
        """Generate path traversal attack request"""
        payloads = [
            "../../etc/passwd",
            "....//....//....//windows/system32/config/sam",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        return {
            'url': f'/download?file={np.random.choice(payloads)}',
            'headers': '{"User-Agent": "Mozilla/5.0"}',
            'body': '',
            'label': 1  # Malicious
        }
    
    def _generate_command_injection_request(self):
        """Generate command injection attack request"""
        payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "`rm -rf /`"
        ]
        
        return {
            'url': f'/api/execute?command=ping{np.random.choice(payloads)}',
            'headers': '{"User-Agent": "Mozilla/5.0"}',
            'body': f'cmd=ping{np.random.choice(payloads)}',
            'label': 1  # Malicious
        }
    
    def extract_features(self, df):
        """
        Extract features from request data for ML training
        """
        print("🔍 Extracting features...")
        
        features = []
        
        for _, row in df.iterrows():
            feature_vector = {}
            
            # URL features
            url = row['url']
            feature_vector['url_length'] = len(url)
            feature_vector['num_params'] = url.count('?') + url.count('&')
            feature_vector['has_special_chars'] = len(re.findall(r'[<>"\']', url)) > 0
            
            # Header features
            headers = json.loads(row['headers'])
            feature_vector['user_agent_length'] = len(headers.get('User-Agent', ''))
            feature_vector['has_suspicious_ua'] = any(ua in headers.get('User-Agent', '').lower() 
                                                     for ua in ['sqlmap', 'nikto', 'nmap'])
            
            # Body features
            body = row['body']
            feature_vector['body_length'] = len(body)
            feature_vector['body_entropy'] = self._calculate_entropy(body)
            
            # Combined text for TF-IDF
            feature_vector['combined_text'] = f"{url} {headers} {body}"
            
            features.append(feature_vector)
        
        return pd.DataFrame(features)
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def prepare_features(self, df):
        """
        Prepare features for ML training
        """
        # Extract basic features
        feature_df = self.extract_features(df)
        
        # TF-IDF on combined text
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=2
        )
        
        tfidf_features = self.vectorizer.fit_transform(feature_df['combined_text'])
        
        # Numerical features
        numerical_features = feature_df[[
            'url_length', 'num_params', 'has_special_chars',
            'user_agent_length', 'has_suspicious_ua',
            'body_length', 'body_entropy'
        ]].values
        
        # Scale numerical features
        numerical_features_scaled = self.scaler.fit_transform(numerical_features)
        
        # Combine features
        X_combined = np.hstack([tfidf_features.toarray(), numerical_features_scaled])
        y = df['label'].values
        
        # Store feature names for interpretability
        tfidf_feature_names = self.vectorizer.get_feature_names_out()
        numerical_feature_names = [
            'url_length', 'num_params', 'has_special_chars',
            'user_agent_length', 'has_suspicious_ua',
            'body_length', 'body_entropy'
        ]
        self.feature_names = list(tfidf_feature_names) + numerical_feature_names
        
        return X_combined, y
    
    def train_model(self, save_model=True):
        """
        Train the ML model
        """
        print("🤖 Training ML model...")
        
        # Generate or load training data
        try:
            df = pd.read_csv('data/training/training_data.csv')
            print("✅ Loaded existing training data")
        except FileNotFoundError:
            df = self.generate_training_data()
        
        # Prepare features
        X, y = self.prepare_features(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest classifier
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X, y, cv=5)
        
        print(f"📊 Model Performance:")
        print(f"   Training Accuracy: {train_score:.4f}")
        print(f"   Test Accuracy: {test_score:.4f}")
        print(f"   Cross-validation: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Detailed classification report
        y_pred = self.model.predict(X_test)
        print("\n📈 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
        
        # Feature importance
        self._analyze_feature_importance()
        
        # Save model and components
        if save_model:
            self.save_model()
            self._save_training_report(X_test, y_test, y_pred)
        
        return self.model
    
    def _analyze_feature_importance(self):
        """Analyze and display feature importance"""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1]
            
            print("\n🔍 Top 10 Most Important Features:")
            for i in range(min(10, len(importances))):
                print(f"   {i+1:2d}. {self.feature_names[indices[i]]:30s} {importances[indices[i]]:.4f}")
    
    def save_model(self):
        """Save trained model and components"""
        os.makedirs('models', exist_ok=True)
        
        joblib.dump(self.model, 'models/trained_model.pkl')
        joblib.dump(self.vectorizer, 'models/vectorizer.pkl')
        joblib.dump(self.scaler, 'models/feature_scaler.pkl')
        
        # Save feature names
        with open('models/feature_names.json', 'w') as f:
            json.dump(self.feature_names, f)
        
        print("💾 Model saved successfully")
    
    def load_model(self):
        """Load trained model and components"""
        try:
            self.model = joblib.load('models/trained_model.pkl')
            self.vectorizer = joblib.load('models/vectorizer.pkl')
            self.scaler = joblib.load('models/feature_scaler.pkl')
            
            with open('models/feature_names.json', 'r') as f:
                self.feature_names = json.load(f)
            
            print("✅ Model loaded successfully")
            return True
        except FileNotFoundError:
            print("[!] Model files not found")
            return False
    
    def predict(self, request_features):
        """
        Predict if request is malicious
        """
        if self.model is None:
            self.load_model()
        
        # Transform features
        text_features = self.vectorizer.transform([request_features['combined_text']])
        
        numerical_features = np.array([
            request_features['url_length'],
            request_features['num_params'],
            request_features['has_special_chars'],
            request_features['user_agent_length'],
            request_features['has_suspicious_ua'],
            request_features['body_length'],
            request_features['body_entropy']
        ]).reshape(1, -1)
        
        numerical_features_scaled = self.scaler.transform(numerical_features)
        
        # Combine features
        X = np.hstack([text_features.toarray(), numerical_features_scaled])
        
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        return {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': probability[1] if prediction == 1 else probability[0],
            'probabilities': {
                'benign': probability[0],
                'malicious': probability[1]
            }
        }
    
    def retrain_model(self, new_data):
        """
        Retrain model with new data (incremental learning)
        """
        print("🔄 Retraining model with new data...")
        
        # Load existing training data
        try:
            existing_df = pd.read_csv('data/training/training_data.csv')
        except FileNotFoundError:
            existing_df = pd.DataFrame()
        
        # Combine with new data
        if isinstance(new_data, pd.DataFrame):
            combined_df = pd.concat([existing_df, new_data], ignore_index=True)
        else:
            # Assume new_data is a list of dictionaries
            new_df = pd.DataFrame(new_data)
            combined_df = pd.concat([existing_df, new_df], ignore_index=True)
        
        # Remove duplicates
        combined_df = combined_df.drop_duplicates()
        
        # Save updated dataset
        combined_df.to_csv('data/training/training_data.csv', index=False)
        
        # Retrain model
        self.train_model(save_model=True)
    
    def _save_training_report(self, X_test, y_test, y_pred):
        """Save detailed training report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'model_type': 'RandomForestClassifier',
            'accuracy': accuracy_score(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
        
        with open('models/training_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Create visualization
        self._create_performance_plot(y_test, y_pred)
    
    def _create_performance_plot(self, y_test, y_pred):
        """Create performance visualization"""
        plt.figure(figsize=(12, 4))
        
        # Confusion Matrix
        plt.subplot(1, 2, 1)
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        
        # Feature Importance (top 10)
        plt.subplot(1, 2, 2)
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[-10:]
            plt.barh(range(10), importances[indices])
            plt.yticks(range(10), [self.feature_names[i] for i in indices])
            plt.title('Top 10 Feature Importances')
        
        plt.tight_layout()
        plt.savefig('models/performance_plot.png', dpi=300, bbox_inches='tight')
        plt.close()

# Utility function for real-time feature extraction
def extract_request_features(request_data):
    """
    Extract features from live HTTP request for prediction
    """
    features = {}
    
    # URL features
    url = request_data.get('url', '')
    features['url_length'] = len(url)
    features['num_params'] = url.count('?') + url.count('&')
    features['has_special_chars'] = len(re.findall(r'[<>"\']', url)) > 0
    
    # Header features
    headers = request_data.get('headers', {})
    features['user_agent_length'] = len(headers.get('User-Agent', ''))
    features['has_suspicious_ua'] = any(ua in headers.get('User-Agent', '').lower() 
                                       for ua in ['sqlmap', 'nikto', 'nmap'])
    
    # Body features
    body = request_data.get('body', '')
    features['body_length'] = len(body)
    features['body_entropy'] = calculate_entropy(body)
    
    # Combined text for TF-IDF
    features['combined_text'] = f"{url} {json.dumps(headers)} {body}"
    
    return features

def calculate_entropy(text):
    """Calculate Shannon entropy of text"""
    if not text:
        return 0
        
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

if __name__ == '__main__':
    # Train the model
    trainer = MLModelTrainer()
    model = trainer.train_model()
    
    # Test with sample requests
    print("\n🧪 Testing with sample requests:")
    
    # Benign request
    benign_request = {
        'url': '/home',
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'body': 'username=user&password=pass123'
    }
    benign_features = extract_request_features(benign_request)
    benign_result = trainer.predict(benign_features)
    print(f"Benign Request: {benign_result}")
    
    # Malicious request (SQLi)
    malicious_request = {
        'url': "/login?username=admin' OR 1=1--",
        'headers': {'User-Agent': 'sqlmap/1.0'},
        'body': "username=admin' OR 1=1--&password=test"
    }
    malicious_features = extract_request_features(malicious_request)
    malicious_result = trainer.predict(malicious_features)
    print(f"Malicious Request: {malicious_result}")
