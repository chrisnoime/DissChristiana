from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

class Reader():
    def __init__(self,ID, reader_quote):
        self.ID = ID #identidade do leitor  
        self.quote = reader_quote
        self.group_quote = reader_quote  #utilizada para o cálculo XOR na etapa coletiva
    
        # gera a chave privada ECDH
        self.reader_private_key_ECDH = ec.generate_private_key(ec.SECP192R1())  
        self.reader_public_key_ECDH = self.reader_private_key_ECDH.public_key()

    def read_tag_quote(self, tag_quote):
        self.tag_quote = tag_quote

    def read_tag_hash(self, tag_hashe):
        # Verificação do Hash
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(self.tag_quote.to_bytes(24, 'big'))
        verification = digest.finalize()
        if verification == tag_hashe:
            self.group_quote ^= self.tag_quote
            return True
        else:
            return False

    #envia a quota do grupo para o servidor
    def authenticate_with_server(self):
        return self.group_quote

    #reinicia a quota do grupo como a quota do servidor
    def restart(self):
        self.group_quote = self.quote

    #envia a chave pública ECDH para a etiqueta
    def send_reader_public_key_ECDH(self):
        return (self.reader_public_key_ECDH)

    def verify_signature(self,signature, ECDH_key, ECDSA_key):# Verificação da assinatura ECDSA
        verification = ECDSA_key.verify(signature, ECDH_key, ec.ECDSA(hashes.SHA3_256()))
        if verification != None:
            #print('assinatura ECDSA da etiqueta não é válida')
            return False
        else:
            #print("assinatura ECDSA da etiqueta válida")
            return True
    
    #gera a chave compartilhada ECDH
    def generate_shared_key(self, tag_public_key_ECDH):
        shared_key = self.reader_private_key_ECDH.exchange(ec.ECDH(), tag_public_key_ECDH)
        return shared_key

    #Cria a função para decriptar o AES
    def decrypt(self, key, associated_data, iv, cipher_text, tag_1):
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag_1)).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        decryptor.authenticate_additional_data(associated_data)

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(cipher_text) + decryptor.finalize()

      


