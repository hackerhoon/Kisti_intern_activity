import pandas as pd
import numpy as np
from tqdm import tqdm
import os,time
import gc
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler

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

def convert_list(x):
    return eval(x)

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
    'normalized_bd': convert_list,
    'notasciistr' : convert_int,
    'length': convert_int,
    'analyResult': convert_int,
    }
    data = pd.read_csv(filename,sep=',',encoding = 'utf-8', converters=datatype,on_bad_lines='warn')
    return data

def LearningModel():
    savepath = 'C:\\Users\\admin\\Desktop\\TASK\\'
    datalist = os.listdir(savepath+'testlearning')
    scaler = MinMaxScaler()
    #bar = tqdm(total=len(datalist),position=0)
    rfc = RandomForestClassifier(n_estimators=10, random_state=2022, warm_start=True)
    
    x_test = []
    y_test = []
    errorlog = []
    train_predict = []
    for file in datalist:

        print(file)
        f = '\\'.join([savepath+'feature',file])
        df = LoadData(f)
        normalized_bd = []

        X = df[['sourcePort', 'destinationPort' ,
                  'directionType' ,'jumboPayloadFlag' ,
                  'packetSize' ,'eventCount', 
                  'notasciistr','length']].values.tolist()
        np_nbd = df['normalized_bd']
        X_ =[]
        
        for (i,j) in zip(X,np_nbd):
            X_.append(i+j)

        X = np.array(X_)
 
        Y = df['analyResult']
       
  
        try:
            x_train, mini_x_test, y_train, mini_y_test = train_test_split(X,Y,test_size = 0.1, shuffle = True, stratify = Y, random_state=2022)
        except:
            x_train, mini_x_test, y_train, mini_y_test = train_test_split(X,Y,test_size = 0.1, shuffle = True, random_state=2022)
        
        rfc.fit(x_train,y_train)
        rfc.n_estimators += 1
        
        print(x_train.shape)
        print(mini_x_test.shape)
        print(y_train.shape)
        print(mini_y_test.shape)

        y_pred = rfc.predict(x_train)
        train_predict.append(accuracy_score(y_true = y_train, y_pred = y_pred))

        x_test += mini_x_test.tolist()
        y_test += mini_y_test.tolist()


        #bar.update()
        
    #bar.close()
    
    return rfc,x_test,y_test,train_predict

def PredictModel(rfc,x_test,y_test):
    print('learning!')
    y_pred = rfc.predict(x_test)
    acc = accuracy_score(y_true = np.array(y_test), y_pred = y_pred)
    print('Test set')
    print(f"정확도(accuracy):{acc:0.4f}")


if __name__ == '__main__':
    rfc,x_test,y_test,train_predict = LearningModel()
    print(train_predict)
    PredictModel(rfc,x_test,y_test)