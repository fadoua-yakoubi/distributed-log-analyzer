# WORKER2.PY - Reçoit les logs, fait la prédiction BERT et renvoie au Master
from flask import Flask, request, jsonify
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import json
import os
import requests
from datetime import datetime
import time

app = Flask(__name__)

# Configuration
MASTER_URL = "https://429fe9db8786.ngrok-free.app/receive_result"  # URL du master 

# CHARGEMENT DU MODÈLE BERT
try:
    training_args_path = '../../model/bert_log_detector/training_args.bin'
    if os.path.exists(training_args_path):
        os.rename(training_args_path, training_args_path + '.backup')
        print( "training_args.bin renommé")
    
    tokenizer = AutoTokenizer.from_pretrained('../../model/bert_log_detector/')
    print(" Tokenizer chargé")
    
    model = AutoModelForSequenceClassification.from_pretrained(
        '../model/bert_log_detector/',
        local_files_only=True
    )
    model.to('cpu')
    model.eval()
    print(" Modèle chargé")
    
    with open('../../model/bert_log_detector/config.json', 'r') as f:
        config = json.load(f)
    
    # Mapping des labels
    label_mapping = {
        'LABEL_0': 'Normal',
        'LABEL_1': 'CommandInjection',
        'LABEL_2': 'PathTraversal',
        'LABEL_3': 'SQLi',
        'LABEL_4': 'SuspiciousUA',
        'LABEL_5': 'XSS'
    }
    
    label_encoder = {i: label_mapping[f'LABEL_{i}'] for i in range(6)}
    
    MODEL_LOADED = True
    print(" Modèle BERT chargé avec succès!")
    print(f" Mapping des labels: {label_encoder}")

except Exception as e:
    print(f" Erreur lors du chargement du modèle: {e}")
    MODEL_LOADED = False
    model = None
    tokenizer = None
    label_encoder = None

# FONCTION DE PRÉDICTION
def predict_attack_type(text):
    """Prédiction avec BERT"""
    if not MODEL_LOADED:
        return "ERREUR", 0.0

    try:
        inputs = tokenizer(
            text,
            add_special_tokens=True,
            max_length=128,
            padding='max_length',
            truncation=True,
            return_tensors='pt',
            return_attention_mask=True
        )
        
        inputs = {k: v.to(model.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=1)
            predicted_class_idx = torch.argmax(outputs.logits, dim=1).item()
            confidence = probabilities[0, predicted_class_idx].item()

        return label_encoder.get(predicted_class_idx, f"UNKNOWN_{predicted_class_idx}"), confidence
        
    except Exception as e:
        print(f" Erreur: {e}")
        return "ERREUR", 0.0

# ROUTES FLASK
@app.route("/process_log", methods=["POST"])
def process_log():
    """Reçoit un log du master, fait la prédiction et renvoie le résultat"""
    start_time = time.time()
    
    log_data = request.json
    print("\n" + "="*100)
    print("LOG REÇU DU MASTER")
    print("="*100)
    print(f" Timestamp: {log_data.get('timestamp')}")
    print(f" Endpoint: {log_data.get('endpoint')}")
    print(f" IP: {log_data.get('ip')}")
    print(f" Type réel: {log_data.get('real_category')}")
    print(f" Payload: {log_data.get('payload', '(vide)')}")
    
    bert_input = f"{log_data['endpoint']} [SEP] {log_data['user_agent']} [SEP] {log_data['payload']}"
    
    print(f"\n Input BERT: {bert_input[:100]}...")
    
    # Prédiction
    predicted_category, confidence = predict_attack_type(bert_input)
    
    processing_time = round((time.time() - start_time) * 1000, 2)  # en ms
    
    # Vérifier si la prédiction est correcte
    is_correct = (predicted_category == log_data.get('real_category'))
    
    print(f"\n PRÉDICTION: {predicted_category}")
    print(f" Confiance: {confidence:.4f}")
    print(f"  Temps de traitement: {processing_time}ms")
    print(f"{' CORRECT' if is_correct else ' INCORRECT'}")
    
    # Préparer le résultat à renvoyer au master
    result = {
        "timestamp": log_data.get('timestamp'),
        "real_category": log_data.get('real_category'),
        "predicted_category": predicted_category,
        "confidence": confidence,
        "is_correct": is_correct,
        "processing_time": processing_time,
        "endpoint": log_data.get('endpoint'),
        "ip": log_data.get('ip')
    }
    
    # Renvoyer le résultat au master
    try:
        print(f"\n Envoi du résultat au master...")
        response = requests.post(MASTER_URL, json=result, timeout=5)
        
        if response.status_code == 200:
            print(" Résultat envoyé au master avec succès!")
        else:
            print(f"  Erreur lors de l'envoi au master: {response.status_code}")
    except Exception as e:
        print(f" Erreur d'envoi au master: {str(e)}")
    
    print("="*100 + "\n")
    
    # Répondre au master immédiatement
    return jsonify({
        "status": "processed",
        "predicted_category": predicted_category,
        "confidence": confidence,
        "is_correct": is_correct
    }), 200

@app.route("/health", methods=["GET"])
def health():
    """Endpoint de santé pour vérifier que le worker fonctionne"""
    return jsonify({
        "status": "healthy",
        "model_loaded": MODEL_LOADED,
        "timestamp": datetime.now().isoformat()
    }), 200

if __name__ == "__main__":
    print("\n" + "="*100)
    print(" WORKER - Système de Prédiction BERT")
    print("="*100)
    print(f" Serveur démarré sur: http://127.0.0.1:5002")
    print(f" Modèle BERT: {' Chargé' if MODEL_LOADED else ' Non chargé'}")
    print(f" Master URL: {MASTER_URL}")
    print(f" Utilisez ngrok pour exposer ce port: ngrok http 5002")
    print("="*100 + "\n")
    app.run(port=5002, debug=True)