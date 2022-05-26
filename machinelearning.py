#!/usr/bin/python3


import chunk
from matplotlib import pyplot as plt
import pandas as pd
import dask.dataframe as dd
import os,time
import numpy as np
from tqdm import tqdm
from sklearn import datasets
from sklearn.svm import SVC
from sklearn.model_selection import StratifiedKFold
from sklearn.semi_supervised import SelfTrainingClassifier
from sklearn.metrics import accuracy_score
from sklearn.utils import shuffle
import multiprocessing as mp
from multiprocessing import Pool
import gc

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

def GetMaliciousData(data, maldata, benign_data):
    cnt = 0
    for i,label in enumerate(data['analyResult']):
        cnt += 1 
        if label == 1:
            maldata['uid'].append(data['uid'][i])
            maldata['sourceIP_new'].append(data['sourceIP_new'][i])
            maldata['destinationIP_new'].append(data['destinationIP_new'][i])
            maldata['sourcePort'].append(data['sourcePort'][i])
            maldata['destinationPort'].append(data['destinationPort'][i])
            maldata['protocol'].append(data['protocol'][i])
            maldata['directionType'].append(data['directionType'][i])
            maldata['jumboPayloadFlag'].append(data['jumboPayloadFlag'][i])
            maldata['packetSize'].append(data['packetSize'][i])
            maldata['detectName_md5'].append(data['detectName_md5'][i])
            maldata['attackType'].append(data['attackType'][i])
            maldata['detectStart'].append(data['detectStart'][i])
            maldata['detectEnd'].append(data['detectEnd'][i])
            maldata['orgIDX'].append(data['orgIDX'][i])
            maldata['eventCount'].append(data['eventCount'][i])
            maldata['analyResult'].append(data['analyResult'][i])
            maldata['payload'].append(data['payload'][i])
        else:
            benign_data['uid'].append(data['uid'][i])
            benign_data['sourceIP_new'].append(data['sourceIP_new'][i])
            benign_data['destinationIP_new'].append(data['destinationIP_new'][i])
            benign_data['sourcePort'].append(data['sourcePort'][i])
            benign_data['destinationPort'].append(data['destinationPort'][i])
            benign_data['protocol'].append(data['protocol'][i])
            benign_data['directionType'].append(data['directionType'][i])
            benign_data['jumboPayloadFlag'].append(data['jumboPayloadFlag'][i])
            benign_data['packetSize'].append(data['packetSize'][i])
            benign_data['detectName_md5'].append(data['detectName_md5'][i])
            benign_data['attackType'].append(data['attackType'][i])
            benign_data['detectStart'].append(data['detectStart'][i])
            benign_data['detectEnd'].append(data['detectEnd'][i])
            benign_data['orgIDX'].append(data['orgIDX'][i])
            benign_data['eventCount'].append(data['eventCount'][i])
            benign_data['analyResult'].append(data['analyResult'][i])
            benign_data['payload'].append(data['payload'][i])
    
    return cnt

def SaveMaliciousData(maldata):
    current_time = time.strftime('%H_%M_%S', time.localtime(time.time()))
    filename = f'MaliciousDatalist[{current_time}].csv'
    Maldata = pd.DataFrame({
    'uid': maldata['uid'],
    'sourceIP_new': maldata['sourceIP_new'],
    'destinationIP_new': maldata['destinationIP_new'],
    'sourcePort': maldata['sourcePort'],
    'destinationPort': maldata['destinationPort'],
    'protocol': maldata['protocol'],
    'directionType': maldata['directionType'],
    'jumboPayloadFlag': maldata['jumboPayloadFlag'],
    'packetSize': maldata['packetSize'],
    'detectName_md5': maldata['detectName_md5'],
    'attackType': maldata['attackType'],
    'detectStart': maldata['detectStart'],
    'detectEnd': maldata['detectEnd'],
    'orgIDX': maldata['orgIDX'],
    'eventCount': maldata['eventCount'],
    'analyResult': maldata['analyResult'],
    'payload': maldata['payload']
    })
    headers = Maldata.columns.tolist()
    print(len(Maldata))
    if len(Maldata) > 500000:
        splittimes = len(Maldata)//500000 + 1
        df_split = np.array_split(Maldata,splittimes)
        for i,df in enumerate(df_split):
            tmp=filename.split('.')
            newfilename = f'{i}.'.join(tmp)
            data_df = pd.DataFrame(df,columns=headers)
            data_df.to_csv(newfilename,index=None,escapechar='\r')
    else:
        Maldata.to_csv(filename,index=None,escapechar='\r')



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

def CreateMaliciousDataFile():
    
    dirpath = ['/mnt/c/Users/master/packet_analysis/ML_test/2017_1234','/mnt/c/Users/master/packet_analysis/ML_test/2018_1234/2018_1234']

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
    
    chunksize = 5*(10**5)
    for dp in dirpath:
        filelist = os.listdir(dp)
        bar = tqdm(total=len(filelist),desc=dp.split('/')[-1],position=0)
        maldata = SetDataFrame()
        count = 0
        for file in filelist:
            f = '/'.join([dp,file])
            ck = pd.read_csv(f,sep='\t',encoding = 'utf-8', converters=datatype,chunksize=chunksize)
            #print(data.columns.tolist())
            #input()
            for data in ck:
                count += GetMaliciousData(data, maldata)# -> 여기까지 수정중~
            bar.update(1)
       
        bar.close()
        
        #SaveMaliciousData(maldata)
        print(count)

def analysisdata(datalist,datadict,feature):
    for data in datalist:
        if feature in ['sourcePort', 'destinationPort']:
            dynamic_port = 49152
            if data > 49151:
                if dynamic_port in datadict:
                    datadict[dynamic_port] += 1
                else:
                    datadict[dynamic_port] = 1
            else:
                if data in datadict:
                    datadict[data] += 1
                else:
                    datadict[data] = 1
        else:
            if data in datadict:
                datadict[data] += 1
            else:
                datadict[data] = 1
    #if feature in ['orgIDX','directionType']:
        #print(datadict.keys())
         
def SaveAnalysisResult(datadict,feature):
    sorted_dict = dict(sorted(datadict.items(),key = lambda item:item[1],reverse = True))
    
    df = pd.DataFrame({
        feature : list(sorted_dict.keys()),
        'number': list(sorted_dict.values())
    })

    headers = df.columns.tolist()
    filename = f'benignanal/'+feature+'.csv'

    if len(df) > 500000:
        splittimes = len(df)//500000 + 1
        df_split = np.array_split(df,splittimes)
        for i,df in enumerate(df_split):
            tmp=filename.split('.')
            newfilename = f'{i}.'.join(tmp)
            data_df = pd.DataFrame(df,columns=headers)
            data_df.to_csv(newfilename,index=None,escapechar='\r')
    else:
        df.to_csv(filename,index=None,escapechar='\r')
        

def LoadData():
    dirpath = ['/mnt/c/Users/master/TASK/benigndata']

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

    features = ['sourceIP_new', 'destinationIP_new', 'sourcePort', 'destinationPort', 'protocol', 'directionType', 'jumboPayloadFlag', 'packetSize', 'attackType', 'orgIDX', 'eventCount']
    
    anal = {
    'sourceIP_new' : {},
    'destinationIP_new' : {},
    'sourcePort' : {},
    'destinationPort' : {},
    'protocol' : {},
    'directionType' : {},
    'jumboPayloadFlag' : {},
    'packetSize' : {},
    'attackType' : {},
    'orgIDX' : {},
    'eventCount' : {},
    }
    #uid = {}
    #analyResult={}
    #payload = {}
    #detectName_md5 = {}
    #detectStart = {}
    #detectEnd = {}

    for dp in dirpath:
        filelist = os.listdir(dp)
        bar = tqdm(total=len(filelist),desc=dp.split('/')[-1],position=0)
        for file in filelist:
            f = '/'.join([dp,file])
            data = pd.read_csv(f,sep=',',encoding = 'utf-8', converters=datatype)
            #print(data.columns.tolist())
            #input()
            for feature in features:
                analysisdata(data[feature],anal[feature],feature)
            
            
            del data
            gc.collect()

            bar.update(1)
                
        bar.close()
    for feature in features:
        SaveAnalysisResult(anal[feature],feature)
        #print(count)


def main():
    #CreateMaliciousDataFile()
    LoadData()

main()

