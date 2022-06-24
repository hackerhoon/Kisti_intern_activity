from cProfile import label
import pandas as pd
import numpy as np
#from tqdm import tqdm
import os,time
from datetime import datetime
#import gc
import re
from sklearn.linear_model import Perceptron
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
#from sklearn.externals import joblib
import joblib
import pickle

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
    #'orgIDX': convert_int,~
    'eventCount': convert_int,
    'payload': convert_dtype,
    'normalized_bd': convert_list,
    'notasciistr' : convert_int,
    'length': convert_int,
    'analyResult': convert_int,
    }
    data = pd.read_csv(filename,sep=',',encoding = 'utf-8', converters=datatype)
    data[['sourcePort', 'destinationPort','packetSize']] = data[['sourcePort', 'destinationPort','packetSize']].astype('int32')
    data[['directionType', 'jumboPayloadFlag', 'eventCount', 'length']]=data[['directionType', 'jumboPayloadFlag', 'eventCount', 'length']].astype('int16')
    
    return data


# make a file list
def MakeFileList(extension_list):
    root = os.path.dirname(os.path.abspath(''))
    datalist = []
    for path, dirs, files in os.walk(root):
        
        if '\\port80feature' in path:
            dir_path = os.path.join(root, path)

            for file in files:
                if file[-3:] in extension_list:
                    datalist.append(os.path.join(dir_path, file))
    return datalist


def LearningRFModel(filelist,eta0):
    ppn = Perceptron(eta0=eta0, random_state=2022, n_jobs=-1)

    x_test = []
    y_test = []
    classes = np.array([1,2])
    print('[{}] Start Load Data'.format(datetime.now()))
    
    for idx, file in enumerate(filelist):
        print('[{}]     Load File....({}/{})'.format(datetime.now(), idx+1, len(filelist)))
        df = LoadData(file)
        df.drop(df[df['analyResult'] == -1].index,inplace = True)
        
        X = df[['sourcePort', 'destinationPort', 'directionType', 'jumboPayloadFlag', 'packetSize', 'eventCount', 'length']].values.tolist()
        Y = df['analyResult'].to_numpy()
        nbddf = pd.DataFrame(df['normalized_bd'].tolist()).astype('float16')
        nbddf = nbddf.values.tolist()

        X_ = []

        for i in range(len(Y)):
            X_.append(X[i]+nbddf[i])
        

        X = np.array(X_)

        try:
            x_train, x_test_tmp, y_train, y_test_tmp = train_test_split(X, Y, test_size=0.1, shuffle=True, stratify=Y, random_state=2022)
        except:
            try:
                x_train, x_test_tmp, y_train, y_test_tmp = train_test_split(X, Y, test_size=0.1, shuffle=True, random_state=2022)
            except ValueError:
                x_train = X
                y_train = Y

        
        x_test += x_test_tmp.tolist()
        y_test += y_test_tmp.tolist()
        
        ppn.partial_fit(x_train, y_train, classes=classes)


    print('[{}] Data load complete'.format(datetime.now()))


    print('[{}] Start model training'.format(datetime.now()))
    #rfc.fit(x_train, y_train)

    print('[{}] End model training'.format(datetime.now()))

    return ppn, x_test, y_test

def PredictModel(classifier,x_test,y_test):
    loglist = []
    print('[{}] Start predict'.format(datetime.now()))
    y_pred = classifier.predict(x_test)
    
    acc = accuracy_score(y_true = np.array(y_test), y_pred = y_pred)
    print('[{}] End predict'.format(datetime.now()))
    print("Accuracy: {:0.4f}".format(acc))

    cf = confusion_matrix(y_test, y_pred)
    print(cf)
    loglist.append(acc)
    loglist.append(cf)
    return loglist

def SaveLog(filename,loglist):
    print(f'[{datetime.now()}] Save Log')
    f = open(filename,'w')
    for log in loglist:
        f.write(log+'\n')
    f.close()

if __name__ == '__main__':
    # make file list
    extension_list = ['csv']
    filelist = MakeFileList(extension_list)
    # model training
    for i in range(1,50):
        clf, x_test, y_test = LearningRFModel(filelist,i*0.1)
        
        joblib.dump(clf, f"Models1\\integrated_perceptron(eta0_{i*0.1})_model.pkl")
        classifier = joblib.load(f"Models1\\integrated_perceptron(eta0_{i*0.1})_model.pkl")
        # model test
        loglist = PredictModel(classifier, x_test, y_test)
        SaveLog(f"Models1\\perceptron(eta0_{i*0.1})_log.txt",loglist)