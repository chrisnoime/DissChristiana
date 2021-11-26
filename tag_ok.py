import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

class Tag():
    def __init__(self, ID, even, odd):
        self.ID = ID
        self.even = even
        self.odd = odd
        digest = hashes.Hash(hashes.SHA3_256())     #cria o hash para a quota utilizando o SHA-256
        digest.update(self.even.to_bytes(24, 'big'))
        self.hashe = digest.finalize()  # serializa o hash para envio

        #gera as chaves ECDSA
        self.tag_private_key_ECDSA = ec.generate_private_key(ec.SECP192R1())
        self.tag_public_key_ECDSA = self.tag_private_key_ECDSA.public_key()
        self.serialized_tag_ECDSA_public_key = self.tag_public_key_ECDSA.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.serialized_tag_ECDSA_public_key.splitlines()[0]

        #gera as chaves ECDH
        self.tag_private_key_ECDH = ec.generate_private_key(ec.SECP192R1())
        self.tag_public_key_ECDH = self.tag_private_key_ECDH.public_key()
        self.serialized_tag_public_key_ECDH = self.tag_public_key_ECDH.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.serialized_tag_public_key_ECDH.splitlines()[0]

    def send_quote(self):
        return (self.even)

    def send_hash(self):
        return (self.hashe)  

    def send_tag_public_key_ECDH(self):
        return (self.tag_public_key_ECDH)

    def sign_key(self,):
        #assina a chave ECDH com a ECDSA
        signature = self.tag_private_key_ECDSA.sign(self.serialized_tag_public_key_ECDH, ec.ECDSA(hashes.SHA3_256()))
        return signature

    #gera a chave compartilhada ECDH
    def generate_shared_key(self, received_reader_public_key_ECDH):
        shared_key = self.tag_private_key_ECDH.exchange(ec.ECDH(), received_reader_public_key_ECDH)
        return shared_key
    
    # Cria a função para encriptar o AES
    def encrypt(self, key, associated_data):

        # Gera um vetor de inicialização de 96-bit
        iv = os.urandom(12)

        # Constrói um objeto cifrador AES-GCM Cipher
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv),).encryptor()

        # Os dados associados serão autenticados mas não cifrados.
        encryptor.authenticate_additional_data(associated_data)

        # Encripta o texto em claro e recebe o texto cifrado associado (o contador)
        ciphertext = encryptor.update(f"{self.ID}".encode('utf-8'),) + encryptor.finalize()

        return (iv, ciphertext, encryptor.tag)

# ------------------------------------------------------Etapa de renovação-------------------------------------------------------------------


# renovação da pseudoidentidade utilizando uma HKDF sendo que a quota nativa é utilizada como salt e a função hash é a SHA3-256

    ID_length = 32


    def gera_pseudo_ids(self, CTR):

        K_ID = HKDF(algorithm=hashes.SHA3_256(),length=ID_length,salt=quota_nativa.to_bytes(30, 'big'),info=(CTR+1).to_bytes(10, 'big'))
        key = K_ID.derive(pseudo_ids[CTR])
        #pseudo_ids.append(key)

        #print("as pseudoidentidades derivada são:", pseudo_ids)
        return key

    #hkdf.verify(b"quota", key)


    #gera_pseudo_ids(CTR)

