#!/usr/bin/python3

import dask.dataframe as dd
import pandas as pd
from tqdm import tqdm
import os
from sklearn.linear_model import SGDOneClassSVM
import random
import numpy as np
from sklearn.metrics import classification_report
from sklearn.inspection import permutation_importance
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.metrics import make_scorer
import gc
#from sklearn.preprocessing import StandardScaler

def convert_dtype(x):
    if not x:
        return ''
    try:
        return str(x)   
    except:        
        return ''

def convert_int(x):
    if not x:
        return -1
    try:
        return int(x)
    except:
        try:
            return int(float(x))
        except:
            return -1

def SetDataFrame():
    data = {
    'uid': [],
    'sourceIP_new': [],
    'destinationIP_new': [],
    'sourcePort': [],
    'destinationPort': [],
    'protocol': [],
    'directionType': [],
    'jumboPayloadFlag': [],
    'packetSize': [],
    'detectName_md5': [],
    'attackType': [],
    'detectStart': [],
    'detectEnd': [],
    'orgIDX': [],
    'eventCount': [],
    'analyResult': [],
    'payload': []
    }
    return data


def MappingPort(port):
    if port < 1024:
        return 0 #well known port
    elif port > 49151:
        return 2 #dynamic port
    else:
        return 1 #registered port


def main():

    datatype = {
    'uid' : convert_dtype,
    'sourceIP_new': convert_dtype,
    'destinationIP_new': convert_dtype,
    'sourcePort': convert_int,
    'destinationPort': convert_int,
    'protocol': convert_int,
    'directionType': convert_int,
    'jumboPayloadFlag': convert_dtype,
    'packetSize': convert_int,
    'detectName_md5': convert_dtype,
    'attackType': convert_int,
    'detectStart': convert_dtype,
    'detectEnd': convert_dtype,
    'orgIDX': convert_int,
    'eventCount': convert_int,
    'analyResult': convert_int,
    'payload': convert_dtype,
    }

    #benigndir = '/mnt/c/Users/master/packet_analysis/benigndata'
    #malwaredir = '/mnt/c/Users/master/packet_analysis/maldata'

    benigndir = 'C:\\Users\\master\\TASK\\benigndata'
    malwaredir = 'C:\\Users\\master\\TASK\\maldata'

    clf = SGDOneClassSVM()
    


    benignlist = os.listdir(benigndir)
    mallist = os.listdir(malwaredir)

    for i in range(30):
        random.shuffle(benignlist)

    total = len(benignlist)
    sttlen = int(total*0.8)
    train_list = benignlist[:sttlen]
    test_list = benignlist[sttlen:] 
    benignlen = len(test_list)
    test_list += mallist

    bar = tqdm(total=total+len(mallist),position=0)
    #cksize = 200000
    for file in train_list:
        f = '\\'.join([benigndir,file])
        #f = '/'.join([benigndir,file])
        
        #여기에 학습

        dask = dd.read_csv(f,sep=',',encoding = 'utf-8', converters=datatype) #ck = pd.read_csv(f,sep='\t',encoding = 'utf-8', converters=datatype,chunksize=csize) #for data in ck:
        data = dask.compute()
    #Y = data['analyResult'].to_numpy()
    #['uid','sourceIP_new','destinationIP_new','protocol','detectName_md5','detectStart','detectEnd','analyResult','payload']
  
        X = data[['sourcePort', 'destinationPort' ,'directionType' ,'jumboPayloadFlag' ,'packetSize' ,'attackType' ,'orgIDX' ,'eventCount']].to_numpy()
        np.place(X,X=='True',1)
        np.place(X,X=='False',0)
        clf.partial_fit(X)
        del dask
        del data
        del X
        gc.collect()
        bar.update(1)
    
    
    y_true = []
    y_pred = []
    for i,file in enumerate(test_list):
        if i <= benignlen:
            f = '\\'.join([benigndir,file])
            #f = '/'.join([benigndir,file])
        else:
            f = '\\'.join([malwaredir,file])
            #f = '/'.join([malwaredir,file])

        dask = dd.read_csv(f,sep=',',encoding = 'utf-8', converters=datatype)
        data = dask.compute()
        y_true += list(data['analyResult'].to_numpy())
        X = data[['sourcePort', 'destinationPort' ,'directionType' ,'jumboPayloadFlag' ,'packetSize' ,'attackType' ,'orgIDX' ,'eventCount']].to_numpy()
        np.place(X,X=='True',1)
        np.place(X,X=='False',0)
        y_pred += list(clf.predict(X))
        #print(len(y_true),len(y_pred))
        del dask
        del data
        del X
        gc.collect()
        bar.update(1)
    y_true = np.array(y_true)
    np.place(y_true ,y_true == 1,-1)
    np.place(y_true,y_true == 2, 1)
    bar.close()
    print(classification_report(y_true, y_pred, labels=[1,2],zero_division=1))
    print("Accuracy", accuracy_score(y_true,y_pred))
    
    
    permX = []
    permY = []
    for file in mallist:
        f = '\\'.join([malwaredir,file])
        
        dask = dd.read_csv(f,sep=',',encoding = 'utf-8', converters=datatype)
        data =dask.compute()
        perm_x = data.sample(frac=0.01,random_state=1004)
        X = perm_x[['sourcePort', 'destinationPort'  ,'directionType' ,'jumboPayloadFlag' ,'packetSize' ,'attackType' ,'orgIDX' ,'eventCount']].to_numpy()
        np.place(X,X=='True',1)
        np.place(X,X=='False',0)
        permX += list(X)
        py = perm_x['analyResult'].to_numpy()
        np.place(py ,py == 1,-1)
        np.place(py,py == 2, 1)
        permY += list(py)
        del X
        del dask
        del data
        del py
        gc.collect()

    for file in benignlist:
        f = '\\'.join([benigndir,file])

        dask = dd.read_csv(f,sep=',',encoding = 'utf-8', converters=datatype)
        data =dask.compute()
        perm_x = data.sample(frac=0.001,random_state=1004)
        X = perm_x[['sourcePort', 'destinationPort' ,'directionType' ,'jumboPayloadFlag' ,'packetSize' ,'attackType' ,'orgIDX' ,'eventCount']].to_numpy()
        np.place(X,X=='True',1)
        np.place(X,X=='False',0)
        permX += list(X)
        py = perm_x['analyResult'].to_numpy()
        np.place(py ,py == 1,-1)
        np.place(py,py == 2, 1)
        permY += list(py)
        del X
        del dask
        del data
        del py
        gc.collect()
    

    scorers = {
        'precision_score': make_scorer(precision_score),
        'recall_score': make_scorer(recall_score),
        'accuracy_score': make_scorer(accuracy_score)
    }
    result = permutation_importance(clf,permX,permY,n_repeats=2,random_state=0,scoring=scorers)
    sorted_idx = result.importances_mean.argsort()

    fig,ax = plt.subplot()
    ax.barh(permX.columns[sorted_idx], result.importances[sorted_idx].mean(axis=1).T)
    ax.set_title("Permutation Importances (test set)")
    fig.tight_layout()
    plt.show()
    
main()