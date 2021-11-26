import secrets
import time
import matplotlib.pyplot as plt
from matplotlib import rcParams
import numpy as np
import tqdm

from reader import Reader
from server import Server
from tag import Tag

#parametros dos gráficos
rcParams["savefig.dpi"] = 150
fontsize = 13
rcParams['font.family'] = 'serif'
rcParams['font.sans-serif'] = ['Times New Roman']
rcParams['font.size'] = fontsize
rcParams['mathtext.fontset'] = 'stix'
rcParams['axes.titlesize'] = fontsize
rcParams['axes.labelsize'] = fontsize


class Group():
    def __init__(self, group_length):
        group_id = secrets.randbits(192)  #geração da chave de grupo
        self.server = Server(group_id) #inicialização do servidor
        reader_quote = group_id                    
        self.tags = []
        
        #geração das quotas e inicialização das etiquetas (cada uma com duas quotas)
        for _ in range(group_length):
            even = secrets.randbits(192)
            odd = secrets.randbits(192)
            ID =secrets.randbits(192)
            reader_quote ^= even
            tag = Tag(ID, even, odd)
            self.tags.append(tag)
        
        self.reader = Reader(ID, group_id^reader_quote) #inicialização do leitor

    #as etiquetas enviam as suas quotas para o leitor que calcula a identidade de grupo
    def calculate_group_id(self):
        for tag in self.tags:
            self.reader.read_tag_quote(tag.send_quote())
            self.reader.read_tag_hash(tag.send_hash())
        return self.reader.group_quote
    
    #leitor envia a identidade do grupo para autenticação no servidor
    def authenticate_group(self):
            self.server.authenticate_group(self.reader.authenticate_with_server())
           
    def get_group_id(self):
        return self.group_id
    

if __name__ == '__main__':
    
    #lista para armazenar as amostras do experimento
    experiments_list = []
    #loop para coletar amostras no experimento
    for _ in tqdm.tqdm(range(2)):
        authentication_durations = []
        #execução do protocolo para diferentes quantidades de etiquetas, 
        # teste da escalabilidade do protocolo. a complexidade de tempo na autenticação está 
        # sendo coletada através da função time()
        for group_len in range(2, 5):
            group = Group(group_len)
            group.calculate_group_id()
            tic = time.time()
            group.authenticate_group() 
            toc = time.time()
            authentication_durations.append(toc-tic)
        experiments_list.append(authentication_durations)

    #print (authentication_durations) # retorna todos os valores do tempo de processamento
    # plotagem dos resultados do experimento
    experiments_array = np.array(experiments_list)
    experiments_mean = experiments_array.mean(axis=0)
    experiments_std = experiments_array.std(axis=0)
    print(experiments_std.shape)
    number_of_tags = range(2, 5)

    #printa a média e o desvio padrão
    print ("a média é", sum(authentication_durations)/len(authentication_durations))

 # plotagem incluindo a média, desvio padrão e intervalo de confiança
    plt.plot(number_of_tags, authentication_durations)
   
    plt.fill_between(number_of_tags, experiments_mean + experiments_std, experiments_mean - experiments_std, alpha=0.5)

    #definições do gráfico
    plt.title('quantidade de etiquetas vs tempo de processamento')
    plt.xlabel('Quantidade de etiquetas')
    plt.ylabel('Tempo de processamento total')
    plt.savefig('teste3.png')


    #fazer Apresentar uma comparação entre resultado teórico e empírico para uma função de 
    # distribuição de probabilidade (ex: função de distribuição acumulada) de, pelo menos, 
    # uma variável aleatória associada ao processo.
    
