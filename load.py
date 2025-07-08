import requests
import threading
import time
import random
import os

BASE_URL = "http://localhost:5000"
DATA_1KB = os.urandom(1024)  # 1KB данных

def sign_request():
    payload = {
        "data": DATA_1KB.hex(),
        "value": random.randint(0, 255),
        "bit_length": 16
    }
    start_time = time.time()
    response = requests.post(f"{BASE_URL}/sign", json=payload)
    latency = (time.time() - start_time) * 1000  # мс
    return latency

def verify_request(signature, proof, public_key):
    payload = {
        "data": DATA_1KB.hex(),
        "signature": signature,
        "proof": proof,
        "public_key": public_key
    }
    start_time = time.time()
    response = requests.post(f"{BASE_URL}/verify", json=payload)
    latency = (time.time() - start_time) * 1000  # мс
    return latency

def worker():
    while True:
        # 70% sign, 30% verify
        if random.random() < 0.7:
            sign_request()
        else:
            # Получаем данные из предыдущего sign (имитация)
            dummy_signature = "a1b2c3..."
            dummy_proof = ["123", "456"]
            dummy_pubkey = "x1y2z3..."
            verify_request(dummy_signature, dummy_proof, dummy_pubkey)

# Запуск 1000 потоков
threads = []
for _ in range(1000):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

for t in threads:
    t.join()