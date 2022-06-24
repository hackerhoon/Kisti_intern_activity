import pandas as pd
import numpy as np
from tqdm import tqdm
import os,time
from datetime import datetime
import gc
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import confusion_matrix
from sklearn.externals import joblib
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
    #'orgIDX': convert_int,
    'eventCount': convert_int,
    'payload': convert_dtype,
    'normalized_bd': convert_list,
    'notasciistr' : convert_int,
    'length': convert_int,
    'analyResult': convert_int,
    }
    data = pd.read_csv(filename,sep=',',encoding = 'utf-8', converters=datatype)
    return data


# make a file list
def MakeFileList(extension_list):
    root = os.path.dirname(os.path.abspath(__file__))
    datalist = []
    for path, dirs, files in os.walk(root):
        dir_path = os.path.join(root, path)
        for file in files:
            if file[-3:] in extension_list:
                datalist.append(os.path.join(dir_path, file))
    return datalist

def LearningRFModel(filelist):
    rfc = RandomForestClassifier(n_estimators=10, random_state=2022)

    x_train = []
    y_train = []
    x_test = []
    y_test = []

    print('[{}] Start Load Data'.format(datetime.now()))
    for idx, file in enumerate(filelist):
        print('[{}]     Load File....({}/{})'.format(datetime.now(), idx+1, len(filelist)))
        df = LoadData(file)

        X = df[['sourcePort', 'destinationPort', 'directionType', 'jumboPayloadFlag', 'packetSize', 'eventCount', 'notasciistr', 'length']].values.tolist()
        Y = df['analyResult'].to_numpy()
        np_nbd = df['normalized_bd']
        X_ = []

        for (i, j) in zip(X, np_nbd):
            X_.append(i+j)
        X = np.array(X_)

        try:
            x_train_tmp, x_test_tmp, y_train_tmp, y_test_tmp = train_test_split(X, Y, test_size=0.1, shuffle=True, stratify=Y, random_state=2022)
        except:
            x_train_tmp, x_test_tmp, y_train_tmp, y_test_tmp = train_test_split(X, Y, test_size=0.1, shuffle=True, random_state=2022)

        x_test += x_test_tmp.tolist()
        y_test += y_test_tmp.tolist()
        x_train += x_train_tmp.tolist()
        y_train += y_train_tmp.tolist()

    print('[{}] Data load complete'.format(datetime.now()))


    print('[{}] Start model training'.format(datetime.now()))
    rfc.fit(x_train, y_train)

    print('[{}] End model training'.format(datetime.now()))

    return rfc, x_test, y_test

def PredictModel(classifier,x_test,y_test):
    print('[{}] Start predict'.format(datetime.now()))
    y_pred = classifier.predict(x_test)

    acc = accuracy_score(y_true = np.array(y_test), y_pred = y_pred)
    print('[{}] End predict'.format(datetime.now()))
    print("Accuracy: {:0.4f}".format(acc))

    cf = confusion_matrix(y_test, y_pred)
    print(cf)


if __name__ == '__main__':
    # make file list
    extension_list = ['csv']
    filelist = MakeFileList(extension_list)

    # model training
    rfc, x_test, y_test = LearningRFModel(filelist)

    joblib.dump(rfc, "integrated_model.pkl")
    classifier = joblib.load("integrated_model.pkl")

    # model test
    PredictModel(classifier, x_test, y_test)