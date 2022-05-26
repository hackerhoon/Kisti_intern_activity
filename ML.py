import pandas as pd
import numpy as np
from tqdm import tqdm
import os,time
import gc
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

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

    

def LoadData(filename):
    datatype = {
    #'uid' : convert_dtype,
    #'sourceIP_new': convert_dtype,
    #'destinationIP_new': convert_dtype,
    'sourcePort': convert_int,
    'destinationPort': convert_int,
    #'protocol': convert_int,
    'directionType': convert_int,
    'jumboPayloadFlag': convert_int,
    'packetSize': convert_int,
    #'detectName_md5': convert_dtype,
    #'attackType': convert_int,
    #'detectStart': convert_dtype,
    #'detectEnd': convert_dtype,
    #'orgIDX': convert_int,
    'eventCount': convert_int,
    'payload': convert_dtype,
    'mormalized_bd': convert_dtype,
    'notasciistr' : convert_int,
    'length': convert_int,
    'analyResult': convert_int,
    }
    data = pd.read_csv(filename,sep=',',encoding = 'utf-8', converters=datatype,on_bad_lines='warn')
    return data

def main():
    savepath = 'C:\\Users\\admin\\Desktop\\TASK\\'
    mal_list = os.listdir(savepath+'malfeature')
    benign_list = os.listdir(savepath+'benignfeature')

    pattern = '(\d*)_(.*)[(]'
    filelist = []
    p = re.compile(pattern) 
    bar = tqdm(total=len(mal_list)+len(benign_list),position=0)
    
    
    total_x =[]
    total_y = []
    for mal in mal_list:
        filelist.append(p.match(mal).group(0))
        mf = '\\'.join([savepath+'malfeature',mal])
        mdf = LoadData(mf)
        normalized_bd = []
        
        X = mdf[['sourcePort', 'destinationPort' ,
                  'directionType' ,'jumboPayloadFlag' ,
                  'packetSize' ,'eventCount',
                  'notasciistr','length']].to_numpy()

        for bd in mdf['normalized_bd']:
            normalized_bd.append(eval(bd))

        np_nbd = np.array(normalized_bd)
        X = np.concatenate([X,np_nbd],1)
        Y = mdf['analyResult'].to_numpy()

        #mal_x_train, mal_x_test,mal_y_train, mal_y_test =train_test_split(X,Y,test_size =0.1, shuffle = True, stratify = Y, random_state=2022)
        #rfc.fit(mal_x_train, mal_y_train)
        #rfc.n_estimators +=1
        total_x.append(X.tolist())
        total_y.append(Y.tolist())
        bar.update()
        
    for benign in benign_list:
        bf = '\\'.join([savepath+'benignfeature',benign])
        
        for file in filelist:
            if file in benign:

                bdf = LoadData(bf)
                X = bdf[['sourcePort', 'destinationPort' ,
                  'directionType' ,'jumboPayloadFlag' ,
                  'packetSize' ,'eventCount',
                  'notasciistr','length']].to_numpy()

                for bd in bdf['normalized_bd']:
                    normalized_bd.append(eval(bd))

                np_nbd = np.array(normalized_bd)
                X = np.concatenate([X,np_nbd],1)
                Y = bdf['analyResult'].to_numpy()
                #bn_x_train, bn_x_test,bn_y_train, bn_y_test =train_test_split(X,Y,test_size =0.3, shuffle = True, stratify = Y, random_state=2022)
                #rfc.fit(bn_x_train, bn_y_train)
                #rfc.n_estimators +=1
                #x_train.append(bn_x_test.tolist())
                #y_train.append(bn_y_test.tolist())
                #x_test.append(bn_x_test.tolist())
                #y_test.append(bn_y_test.tolist())
                total_x.append(X.tolist())
                total_y.append(Y.tolist())
                break

        bar.update()

    bar.close()

    print('learning!')
    X = np.array(total_x)
    Y = np.array(total_y)
    rfc = RandomForestClassifier(n_estimators=100, random_state=2022, warm_start=True)
    x_train,x_test,y_train,y_test = train_test_split(X,Y,test_size = 0.1, shuffle = True, stratify = Y, random_state=2022)
    y_pred = rfc.predict(x_train)
    acc = accuracy_score(y_true = y_train, y_pred = y_pred)
    print('Train set')
    print(f"정확도(accuracy):{acc:0.4f}")
    y_pred = rfc.predict(x_test)
    acc = accuracy_score(y_true = y_test, y_pred = y_pred)
    print('Test set')
    print(f"정확도(accuracy):{acc:0.4f}")

    print('save train set, test set')
    total_df = pd.DataFrame()
    total_df['x'] = x_train
    total_df['y'] = y_train
    total_df.to_csv('total.csv',index=None,escapechar='\r')


main()
