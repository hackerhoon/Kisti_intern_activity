import pandas as pd
import numpy as np
#from tqdm import tqdm
import os,time
from datetime import datetime
#import gc
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
#from sklearn.externals import joblib
import joblib
import pickle
import matplotlib.pyplot as plt

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
        
        if '\\feature' in path:
            dir_path = os.path.join(root, path)

            for file in files:
                if file[-3:] in extension_list:
                    datalist.append(os.path.join(dir_path, file))
    return datalist


def LearningRFModel(filelist):
    rfc = RandomForestClassifier(n_estimators=16, random_state=2022, n_jobs = -1, warm_start = False)

    x_train = []
    y_train = []
    x_test = []
    y_test = []
    classes = [1,2]
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
            x_train_tmp, x_test_tmp, y_train_tmp, y_test_tmp = train_test_split(X, Y, test_size=0.1, shuffle=True, stratify=Y, random_state=2022)
        except:
            try:
                x_train_tmp, x_test_tmp, y_train_tmp, y_test_tmp = train_test_split(X, Y, test_size=0.1, shuffle=True, random_state=2022)
            except ValueError:
                x_train_tmp = X
                y_train_tmp = Y

        
        x_test += x_test_tmp.tolist()
        y_test += y_test_tmp.tolist()
        x_train += x_train_tmp.tolist()
        y_train += y_train_tmp.tolist()

        #if idx == 0:
        #    rfc.fit(x_train,y_train)
        #else:
        #    rfc.n_estimators += 16
        #    rfc.fit(x_train,y_train)
        #x_train += x_train_tmp.tolist()
        #y_train += y_train_tmp.tolist()

    print('[{}] Data load complete'.format(datetime.now()))


    print('[{}] Start model training'.format(datetime.now()))
    rfc.fit(x_train, y_train, classes= classes)

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


def FeatureImportance(classifier):
    
    print(f'[{datetime.now()}] Start to compute the importances')
    start_time = time.time()
    importance = classifier.feature_importances_
    std = np.std([tree.feature_importances_ for tree in classifier.estimators_], axis=0)
    elapsed_time = time.time() - start_time

    print(f"Elapsed time to compute the importances: {elapsed_time:.3f} seconds")

    return std,importance

if __name__ == '__main__':
    # make file list
    extension_list = ['csv']
    filelist = MakeFileList(extension_list)

    # model training
    rfc, x_test, y_test = LearningRFModel(filelist[:10])

    joblib.dump(rfc, "integrated_model.pkl")
    classifier = joblib.load("integrated_model.pkl")

    # model test
    PredictModel(classifier, x_test, y_test)
    std, importance = FeatureImportance(rfc)
    feature_name = [i for i in range(importance)]
    forest_importances = pd.Series(importance, index=feature_name)

    fig, ax = plt.subplots()
    forest_importances.plot.bar()
    ax.set_title("Feature importances using MDI")
    ax.set_ylabel("Mean decrease in impurity")
    fig.tight_layout()