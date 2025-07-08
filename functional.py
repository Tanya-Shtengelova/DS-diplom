import unittest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from pybulletproofs import zkrp_prove, zkrp_verify

class TestZKPSignatureApp(unittest.TestCase):
    def setUp(self):

        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.small_data = os.urandom(256)  # 256 байт
        self.medium_data = os.urandom(1024)  # 1 КБ
        self.large_data = os.urandom(4096)  # 4 КБ

        self.value = 123
        self.bit_length = 16

    def test_key_pair_generation(self):
        """Проверка генерации ключевой пары Ed25519"""
        priv_key = Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()

        test_data = b"test_data"
        signature = priv_key.sign(test_data)
        pub_key.verify(signature, test_data)

    def test_zkp_proof_verification(self):
        """Проверка работы ZKP (доказательство и верификация)"""
        proof = zkrp_prove(self.value, self.bit_length)
        self.assertTrue(zkrp_verify(proof[0], proof[1], self.bit_length))

    def test_sign_verify_small_data(self):
        """Подпись и верификация сообщения (256 байт)"""
        self._test_sign_verify(self.small_data)

    def test_sign_verify_medium_data(self):
        """Подпись и верификация сообщения (1 КБ)"""
        self._test_sign_verify(self.medium_data)

    def test_sign_verify_large_data(self):
        """Подпись и верификация сообщения (4 КБ)"""
        self._test_sign_verify(self.large_data)

    def _test_sign_verify(self, data):
        signature = self.private_key.sign(data)
        proof = zkrp_prove(self.value, self.bit_length)

        self.public_key.verify(signature, data)

        self.assertTrue(zkrp_verify(proof[0], proof[1], self.bit_length))

    @patch('threading.Thread')
    def test_parallel_verification(self, mock_thread):
        """Проверка параллельной обработки 100 запросов"""
        from concurrent.futures import ThreadPoolExecutor

        def verify_task(data):
            signature = self.private_key.sign(data)
            proof = zkrp_prove(self.value, self.bit_length)
            return (
                self.public_key.verify(signature, data),
                zkrp_verify(proof[0], proof[1], self.bit_length)
            )

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(verify_task, self.small_data) for _ in range(100)]
            results = [f.result() for f in futures]

        for sig_valid, proof_valid in results:
            self.assertTrue(sig_valid)
            self.assertTrue(proof_valid)

    def test_tampered_data(self):
        """Проверка реакции на модифицированные данные"""
        signature = self.private_key.sign(self.small_data)
        tampered_data = self.small_data + b"tampered"

        with self.assertRaises(InvalidSignature):
            self.public_key.verify(signature, tampered_data)

    def test_invalid_signature(self):
        """Проверка неверной подписи (случайные байты)"""
        invalid_signature = os.urandom(64)  # Ed25519 signature size

        with self.assertRaises(InvalidSignature):
            self.public_key.verify(invalid_signature, self.small_data)

    def test_invalid_zkp_proof(self):
        """Проверка некорректного ZKP-доказательства"""
        proof = zkrp_prove(self.value, self.bit_length)
        tampered_proof = (proof[0], proof[1] + "tampered")

        self.assertFalse(zkrp_verify(tampered_proof[0], tampered_proof[1], self.bit_length))

    @patch('socket.socket')
    def test_network_send_receive(self, mock_socket):
        """Тест отправки/получения данных через сокет"""
        mock_conn = MagicMock()
        mock_socket.return_value.accept.return_value = (mock_conn, ('127.0.0.1', 12345))

        test_data = {
            'filename': 'test.txt',
            'file_data': self.small_data.hex(),
            'public_key': self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            'signature': self.private_key.sign(self.small_data).hex(),
            'proof': [str(p) for p in zkrp_prove(self.value, self.bit_length)],
            'value': self.value,
            'bit_length': self.bit_length
        }

        mock_conn.recv.return_value = json.dumps(test_data).encode()

        self.app.handle_client(mock_conn)

        mock_conn.sendall.assert_not_called()
        mock_conn.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()