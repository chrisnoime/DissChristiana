import time
import matplotlib.pyplot as plt
from matplotlib import rcParams
import numpy as np
import tqdm
from hwcounter import Timer, count, count_end

from reader_ok import Reader
from server_ok import Server
from tag_ok import Tag

#parametros dos gráficos
rcParams["savefig.dpi"] = 150
fontsize = 13
rcParams['font.family'] = 'serif'
rcParams['font.sans-serif'] = ['Times New Roman']
rcParams['font.size'] = fontsize
rcParams['mathtext.fontset'] = 'stix'
rcParams['axes.titlesize'] = fontsize
rcParams['axes.labelsize'] = fontsize


class Protocol():
    def __init__(self, group_length):
        self.server = Server(group_length) #inicialização do servidor
        self.tags = []
        reader_quote = self.server.group_id

        #inicialização das etiquetas, recebimento das quotas
        for _ in range(group_length):
            odd = self.server.generate_tag_odd_quote()
            even = self.server.generate_tag_even_quote()
            tag_ID = self.server.generate_tag_id()
            tag = Tag(tag_ID, even, odd)
            reader_quote ^= even
            self.tags.append(tag)
        #inicializa o leitor
        self.reader = Reader(self.server.generate_reader_ID(), reader_quote) 

    #as etiquetas enviam as suas quotas para o leitor que confere os hashes das quotas, e se 
    # forem corretos, calcula a identidade de grupo
    def calculate_group_id(self):
        for tag in self.tags:
            self.reader.read_tag_quote(tag.send_quote())
            if self.reader.read_tag_hash(tag.send_hash()) == True:
                pass
            else: 
                print("etiqueta falsa")
        return self.reader.group_quote
    #leitor envia a identidade do grupo para autenticação no servidor
    def authenticate_group(self):
            if self.server.authenticate_group(self.reader.authenticate_with_server()) == True:
                #print("autenticação coletiva correta")
                pass
            else:
                #print("autenticação coletiva falhou")
                pass
    
    #envia a identidade do grupo
    def get_group_id(self):
        return self.group_id
    
    #etapa de autenticação individual
    def individual_authentication(self):
        for tag in self.tags: #para cada etiqueta do grupo
            # geração das chaves e verificação da assinatura da chave das etiquetas
            if self.reader.verify_signature(tag.sign_key(), 
            tag.serialized_tag_public_key_ECDH, tag.tag_public_key_ECDSA) == True: 
                #define o valor do contador
                CTR=1
                #envia a chave ECDH do leitor para a etiqueta
                received_reader_key = self.reader.send_reader_public_key_ECDH() 
                #a etiqueta gera a chave compartilhada ECDH e encripta a identidade dela
                cipher_text = tag.encrypt(tag.generate_shared_key(received_reader_key), CTR.to_bytes(3, 'big')) 
                (iv, ciphertext, encryptor_tag) = cipher_text 
                
                #o leitor gera a chave compartilhada ECDH 
                shared_key = self.reader.generate_shared_key(tag.send_tag_public_key_ECDH())
                #o leitor decripta a identidade da etiqueta
                plain_text = self.reader.decrypt(shared_key, CTR.to_bytes(3, 'big'), iv, ciphertext, encryptor_tag)
                if self.server.authenticate_tag(int(plain_text)) == True:
                    #print("autenticação individual correta")
                    pass
                else:
                    #print("autenticação individual falhou porque a identidade não foi localizada")
                    break

            else: 
                #print("autenticação falhou porque a assinatura da etiqueta está incorreta")
                break
            

if __name__ == '__main__':

    #lista para armazenar as amostras do experimento
    experiments_list3 = [] #autenticação coletiva - ciclo
    experiments_list4 = [] #autenticação individual - ciclo

    #loop para coletar amostras no experimento
    for _ in tqdm.tqdm(range(1000)):

        #lista que armazena os valores de ciclos de CPU na etapa de autenticação coletiva
        list_cycles_1 = [] 
        #lista que armazena os valores de ciclos de CPU na etapa de autenticação individual
        list_cycles_2 = [] 

        #execução do protocolo para diferentes quantidades de etiquetas, 
        # teste da escalabilidade do protocolo. a complexidade de tempo na autenticação está 
        # sendo coletada através da função time()
        number_of_tags = range(2, 101)
        for group_len in number_of_tags:
            #etapa de inicialização
            group = Protocol(group_len)
            #etapa de autenticação coletiva
            group.calculate_group_id()
            with Timer() as t:
                group.authenticate_group() 
            list_cycles_1.append(t.cycles)
            experiments_list3.append(list_cycles_1)

            #etapa de autenticação individual
            with Timer() as t2:
                group.individual_authentication()
            list_cycles_2.append(t2.cycles)
            experiments_list4.append(list_cycles_2)

#para a etapa de autenticação individual

    #definições do gráfico
    plt.title('Nº de etiquetas vs tempo de processamento')
    plt.xlabel('Quantidade de etiquetas')
    plt.ylabel('Tempo de processamento na etapa de aut. ind.')
    plt.savefig('teste_c.png')


    # plotagem dos resultados do experimento
    experiments_array3 = np.array(experiments_list3)
    experiments_mean3 = experiments_array3.mean(axis=0)
    experiments_std3 = experiments_array3.std(axis=0)
    print(experiments_std3.shape)

    # plotagem incluindo a média, desvio padrão e intervalo de confiança
    plt.plot(number_of_tags, list_cycles_1)
    plt.fill_between(number_of_tags, experiments_mean3 + experiments_std3, experiments_mean3 - experiments_std3, alpha=0.5)

    #definições do gráfico
    plt.title('quantidade de etiquetas vs Nº de ciclos')
    plt.xlabel('Quantidade de etiquetas')
    plt.ylabel('Nº de ciclos na etapa de aut. colet.')
    plt.savefig('teste_b.png')
#para a etapa de autenticação coletiva

    # plotagem dos resultados do experimento
    experiments_array4 = np.array(experiments_list4)
    experiments_mean4 = experiments_array4.mean(axis=0)
    experiments_std4 = experiments_array4.std(axis=0)
    print(experiments_std4.shape)

      # plotagem incluindo a média, desvio padrão e intervalo de confiança

    plt.plot(number_of_tags, list_cycles_2)
    plt.fill_between(number_of_tags, experiments_mean4 + experiments_std4, experiments_mean4 - experiments_std4, alpha=0.5)

    #definições do gráfico
    plt.title('quantidade de etiquetas vs Nº de ciclos')
    plt.xlabel('Quantidade de etiquetas')
    plt.ylabel('Nº de ciclos na etapa de aut. ind.')
    plt.savefig('teste_d.png')

    #printa a média e o desvio padrão
    print ("a média de ciclos na autenticação coletiva é", sum(list_cycles_1)/len(list_cycles_1))
    print ("a média de ciclos na autenticação individual é", sum(list_cycles_2)/len(list_cycles_2))

