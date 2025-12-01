# MASTER.PY - Distribue les logs aux workers
from flask import Flask, request, jsonify
import requests
from datetime import datetime, UTC
from flask_cors import CORS


app = Flask(__name__)
CORS(app) 

# Configuration
WORKERS = [
    #worker 1 :
    "https://unlikably-unremissible-yamileth.ngrok-free.dev/process_log",
     #worker 2 :
    "https://nonduplicative-monet-vividly.ngrok-free.dev/process_log", 


 ]

counter = 0
logs_history = []   # Historique des logs envoyés & résultats reçus


# FONCTION INTERNE → utilisée par /send_log ET /receive_log
def send_log_internal(log):
    """Envoie un log à un worker en round-robin."""
    global counter

    worker_url = WORKERS[counter % len(WORKERS)]
    counter += 1

    print(f"📤 Envoi du log au worker {worker_url}")
    print(f"   Type réel: {log.get('real_category', 'N/A')}")

    try:
        response = requests.post(worker_url, json=log, timeout=10)

        if response.status_code == 200:
            print("   ✅  Log envoyé avec succès")
            logs_history.append({
                "log": log,
                "worker": worker_url,
                "sent_at": datetime.now(UTC).isoformat()
            })

        else:
            print(f"   ❌ Erreur worker: {response.status_code}")

    except Exception as e:
        print(f"   ❌ Erreur d'envoi: {str(e)}")

    return worker_url
    


# ROUTE 1 : le log generator envoie un log → MASTER → worker
@app.route("/receive_log", methods=["POST"])
def receive_log():
    """Reçoit un log du log generator et l'envoie automatiquement via send_log()."""
    log = request.json
    if not log:
        return jsonify({"error": "Aucun log fourni"}), 400

    print(f"Log reçu: {log}")

    worker_used = send_log_internal(log)

    return jsonify({
        "status": "received_and_sent",
        "worker": worker_used
    }), 200



# ROUTE 2 : external manual call if needed
@app.route("/send_log", methods=["POST"])
def send_log_route():
    """Route permettant d'envoyer un log manuellement à un worker."""
    log = request.json
    if not log:
        return jsonify({"error": "Aucun log fourni"}), 400

    worker_used = send_log_internal(log)

    return jsonify({"status": "log_sent", "worker": worker_used}), 200




# Le worker renvoie ses résultats ici

@app.route("/receive_result", methods=["POST"])
def receive_result():
    result = request.json
    print(f"📥 Résultat reçu du worker : {result}")

    # Mise à jour de l'historique
    for entry in logs_history:
        if entry["log"]["timestamp"] == result.get("timestamp"):
            entry["prediction"] = result.get("predicted_category")
            entry["confidence"] = result.get("confidence")
            entry["is_correct"] = result.get("is_correct")
            entry["processing_time"] = result.get("processing_time")
            break

    return jsonify({"status": "result_received"}), 200



# Interface simple
@app.route("/")
def index():
    return jsonify({"logs_history": logs_history})



# MAIN
if __name__ == "__main__":
    print("="*100)
    print("🎯 MASTER ACTIF - Distribution automatique des logs + réception résultats")
    print("="*100)
    print("Serveur : http://127.0.0.1:5000")
    print(f"Workers : {WORKERS}")
    print("="*100)
    app.run(port=5000, debug=True)

