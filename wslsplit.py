#!/usr/bin/python3

import pandas as pd
import dask.dataframe as dd
from tqdm import tqdm
import os,time
import numpy as np
import gc

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

def EncodingResult(analyresult):
    if analyresult == 1:
        return -1
    else:
        return 1

def Bytes2String(bytestring): #bytes to string 
    
    #string = bytestring.decode('utf-8','ignore')
    string = "" 
    for c in bytestring:
        string += chr(c)        

    return string



def SaveData(df,filename):
    #df = pd.DataFrame.from_dict(data)

    headers = df.columns.tolist()
    
    #with open(filename,'w') as f:
    #   df.to_csv(f,index=None,escapechar='\r',columns=headers)

    
    if len(df) > 500000:
        splittimes = len(df)//500000 + 1
        df_split = np.array_split(df,splittimes)
        for i,df in enumerate(df_split):
            tmp=filename.split('.')
            newfilename = f'{i}.'.join(tmp)
            data_df = pd.DataFrame(df,columns=headers)
            with open(newfilename,'w') as f:
                data_df.to_csv(f,index=None,escapechar='\r')
    else:
        with open(filename,'w') as f:
            df.to_csv(f,index=None,escapechar='\r')

    del df
            
            
    
        

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

    #tmp = SetDataFrame()
    dirpath = ['/mnt/c/Users/admin/Desktop/TASK/2017_1234','/mnt/c/Users/admin/Desktop/TASK/2018_1234']
    #dirpath = ['/mnt/d/ML_data/2018_1234']
    #cksize = 500000
    for i,dpath in enumerate(dirpath):
        filelist = os.listdir(dpath)
        bar = tqdm(total=len(filelist),desc=dpath.split('/')[-1],position=0)
        for file in filelist:
            #benigndata = SetDataFrame()
            #maliciousdata = SetDataFrame()
            filename = '/'.join([dpath, file])
            #ck = pd.read_csv(filename,sep='\t',encoding = 'utf-8', converters=datatype,chunksize=cksize,on_bad_lines='warn')
            dask_data = dd.read_csv(filename,delim_whitespace=True,encoding = 'utf-8', converters=datatype)
            data = dask_data.compute()
            savename = file.split('.')[0] # + f'[{i}]'
            #for i,data in enumerate(ck):
                #SplitData(data,benigndata,maliciousdata)
                #SplitData(data,maliciousdata)
            data = data[data['protocol']==6]
            maliciousdata = data[data['analyResult']==1]
            #benigndata = data[data['analyResult']==2]
            if not maliciousdata.empty:
                SaveData(data,f'/mnt/c/Users/admin/Desktop/TASK/formldata/{savename}'+f'({2017+i}).csv')

            #if not benigndata.empty:
            #    SaveData(benigndata,f'/mnt/c/Users/admin/Desktop/TASK/benigndata/{savename}'+f'({2017+i}).csv')

            gc.collect()
            bar.update(1)        
        bar.close()

'''
'Relay-IP'
'WEB-PAT'
'00-IP'
'Attack-IP'
'Attack-PAT'
'Mail-IP'
'Mail-PAT'
'Malware-IP'
'Malware-PAT'
'PROXY-IP'
'RAT-PAT'
'Webshell-PAT'
#그외는 etc~
'''

main()
