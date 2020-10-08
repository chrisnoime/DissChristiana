# -*- coding: utf-8 -*-
"""
Created on Thu Oct  8 10:24:36 2020

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



#valores recebidos na etapa de inicialização

quota = int(input('Qual a sua quota par?'))

#------------------------------------------Váriaveis--------------------------------------------------------------------------------

CTR=0

inicio=True #variavel usada para controlar se é a primeira conexão ou uma subsequente



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
        
        client_socket.send(f"{quota}".encode('utf-8'))
#-----------------------------------------------------etapa de identificação coletiva--------------------------------------------------------        
       

        # Aguarda o recebimento dos dados
    try:
            key_length=struct.unpack('>HH',client_socket.recv(4)) #recebe o comprimento da chave pública
            
                      
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
       