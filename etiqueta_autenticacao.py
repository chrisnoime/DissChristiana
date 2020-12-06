# -*- coding: utf-8 -*-
"""
Created on Fri Oct  2 16:03:19 2020

@author: Dell
"""
import socket
import errno
import os  
import cryptography
import sys
import struct

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


#------------------------------------------Constantes----------------------------------------------------------------------------


IP = "127.0.0.1"
PORT = 1234

ID_length = 32#lembrar que o tamanho tem que ser dado no servidor
CTR_length=2 #XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


#O usuário precisa entrar com os valores das quotas recebidos na etapa de inicialização

quota = int(input('Qual a sua quota par?'))
quota_nativa=int(input('Qual a sua quota impar?'))

#------------------------------------------Váriaveis--------------------------------------------------------------------------------

CTR=0

inicio=True #variavel usada para controlar se é a primeira conexão ou uma subsequente

pseudo_ids=[]#lista com as pseudoidentidades
pseudo_ids.append(quota.to_bytes(30, 'big'))

#-----------------------------------------Geração das chaves ECDSA e ECDH----------------------------------------------------------

# Gera as chaves do ECDH
chave_privada_da_etiqueta_ECDH = ec.generate_private_key(ec.SECP192R1())

chave_publica_da_etiqueta_ECDH = chave_privada_da_etiqueta_ECDH.public_key()

#serializa a chave pública para poder enviar
chave_publica_da_etiqueta_ECDH_serializada = chave_publica_da_etiqueta_ECDH.public_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PublicFormat.SubjectPublicKeyInfo)
chave_publica_da_etiqueta_ECDH_serializada.splitlines()[0]
print("A chave pública ECDH da etiqueta é:", chave_publica_da_etiqueta_ECDH_serializada)

#Gera as chaves do ECDSA
chave_privada_da_etiqueta_ECDSA = ec.generate_private_key(ec.SECP192R1())
chave_publica_da_etiqueta_ECDSA = chave_privada_da_etiqueta_ECDSA.public_key()

chave_publica_da_etiqueta_ECDSA_serializada = chave_publica_da_etiqueta_ECDSA.public_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PublicFormat.SubjectPublicKeyInfo)
chave_publica_da_etiqueta_ECDSA_serializada.splitlines()[0]

print("A chave pública ECDSA da etiqueta é:", chave_publica_da_etiqueta_ECDSA_serializada)

#Gera a assinatura da chave pública do ECDH usando o ECDSA
assinatura = chave_privada_da_etiqueta_ECDSA.sign(chave_publica_da_etiqueta_ECDH_serializada,ec.ECDSA(hashes.SHA3_256()))
print('A assinatura ECDSA da chave pública ECDH da etiqueta é:', assinatura)

#-------------------------------------------Cria a função para encriptar o AES--------------------------------------------------------------


def encrypt(key, plaintext, associated_data):
    # Gera um vetor de inicialização de 96-bit 
    iv = os.urandom(12)

    # Constrói um objeto cifrador AES-GCM Cipher 
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    # Os dados associados serão autenticados mas não cifrados. 
    encryptor.authenticate_additional_data(associated_data)

    # Encripta o texto em claro e recebe o texto cifrado associado (o contador) 
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)

#------------------------------------------------------Etapa de renovação-------------------------------------------------------------------


#renovação da pseudoidentidade utilizando uma HKDF sendo que a quota nativa é utilizada como salt e a função hash é a SHA3-256

ID_length = 32

def gera_pseudo_ids(CTR):

    K_ID = HKDF(
        algorithm=hashes.SHA3_256(),
        length=ID_length,
        salt=quota_nativa.to_bytes(30,'big'),
        info=(CTR+1).to_bytes(10,'big')
        )
    key = K_ID.derive(pseudo_ids[CTR])
    pseudo_ids.append(key)

    print("as pseudoidentidades derivada são:", pseudo_ids)
    return key

#hkdf.verify(b"quota", key)

gera_pseudo_ids(CTR)

#------------------------------------------------------Parte da comunicação------------------------------------------------------------------------
# Cria uma soquete da família IPv4 e conexão TCP

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conecta a um dado endereço IP e porta 
client_socket.connect((IP, PORT))

# Coloca a conexão em um estado de não bloqueio, então .recv() não vai bloquear, só retornar uma exceção
client_socket.setblocking(False)

while inicio==True:         
  
        # Cria um loop para o recebimento de mensagens mas o usuário precisa informar que houve conexão

  
    evento=input('Ocorreu conexão com o leitor?')
    
    # Se um evento ocorreu, envia as quotas e a chave pública para a etiqueta
    if evento:
        lengths=(len(f"{pseudo_ids[1]}"),len(f"{quota}"),len(chave_publica_da_etiqueta_ECDH_serializada),len(chave_publica_da_etiqueta_ECDSA_serializada),len(assinatura))
        print("Início da comunicação com o leitor")
        total_length=int.from_bytes(lengths, byteorder ='big')
        
        
        client_socket.send(total_length.to_bytes(5, 'big')+f"{pseudo_ids[1]}".encode('utf-8') +f"{quota}".encode('utf-8')+
                           chave_publica_da_etiqueta_ECDH_serializada+chave_publica_da_etiqueta_ECDSA_serializada+assinatura)
#-----------------------------------------------------etapa de identificação coletiva--------------------------------------------------------        
       

        # Aguarda o recebimento dos dados
    try:
            key_length=struct.unpack('>HH',client_socket.recv(4)) #recebe o comprimento da chave pública
            
            #recebe a chave pública ECDH do leitor e a formata para o formato correto
            chave_publica_do_leitor=client_socket.recv(key_length[1])
            chave_publica_recebida = serialization.load_pem_public_key(chave_publica_do_leitor)
    
            
            print("A chave pública do ECDH do leitor é:", chave_publica_recebida)
            
            
         #Gera a chave compartilhada
            chave_compartilhada = chave_privada_da_etiqueta_ECDH.exchange(ec.ECDH(), chave_publica_recebida)
            print("A chave compartilhada criada pelo ECDH para o AES é::", chave_compartilhada)
         
            inicio=False
             
#-----------------------------------------Tratamento de erros--------------------------------------------------------------

    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()

        # We just did not receive anything
                #continue

    except Exception as e:
            # Any other exception - something happened, exit
                print('Reading error: '.format(str(e)))
                sys.exit() 
                
     #Envia a informação encriptada   
       
#----------------------------------Comunicações das pseudo identidades encriptadas pelo AES, cada comunicação aumenta em 1 o counter---------------------------------
if inicio==False:
    while True:
        evento = input('Ocorreu conexão?')
    
    # Se um evento ocorreu, envia as quotas e a chave pública para a etiqueta
        if evento:
            
        #Encripta as informações da pseudoidentidade encriptadas pelo AES usando a chave compartilhada criada pelo ECDH e o valor do contador 
            CTR+=1
            K_ID=gera_pseudo_ids(CTR)
            info_encriptada=encrypt(chave_compartilhada, f"{K_ID}".encode('utf-8'), CTR.to_bytes(3, 'big'))
            print("O valor atual do contador é:", CTR,"e a informação enviada é:", info_encriptada[0],type(info_encriptada[0]),len(info_encriptada[0]),info_encriptada[1],type(info_encriptada[1]),len(info_encriptada[1]),info_encriptada[2],type(info_encriptada[2]),len(info_encriptada[2]))
        
        #e envia essas informações
            client_socket.send(b'ok')
        
            client_socket.send(CTR.to_bytes(3, 'big')+info_encriptada[0]+info_encriptada[2]+info_encriptada[1]) 
        