#!/usr/bin/python3
import pandas as pd
import numpy as np
import dask.dataframe as dd
from tqdm import tqdm
import os,time
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

def Hex2Ascii(data): return b''.fromhex(data)

def Bytes2String(bytestring): #bytes to string 
    
    #string = bytestring.decode('utf-8','ignore')
    string = "" 
    for c in bytestring:
        string += chr(c)        

    return string

def Bytes2String2(bytestring): return bytestring.decode('utf-8','ignore')

def ByteDistribution(payloadlist):
    bytedistribution = [[0 for j in range(256)] for i in range(len(payloadlist))]
    normalized_bd = []
    notasciistring = [0 for i in range(len(payloadlist))]
    stringlength = []
    for i,payload in enumerate(payloadlist):
        ascii_payload = Hex2Ascii(payload)
        stringlength.append(len(ascii_payload))
        normalizing = []
        zeroflag = 0
        for j in range(len(ascii_payload)):
            try:
                bytedistribution[i][ascii_payload[j]] += 1
            except:
                notasciistring[i] +=1
        
        for j in range(256):
            if sum(bytedistribution[i]) != 0:
                normalizing.append(bytedistribution[i][j]/sum(bytedistribution[i]))
            else:
                zeroflag = 1
        
        if zeroflag == 1:
            normalized_bd.append(bytedistribution[i])
        else:
            normalized_bd.append(normalizing)
    
    del bytedistribution 

    return normalized_bd, notasciistring, stringlength

def PayloadDecoding(payload):
    decodedlist=[]
    for pay in payload:
        decodedlist.append(Bytes2String2(Hex2Ascii(pay)))
    return decodedlist #데이터 프레임 변환필요

def LoadData(filename):
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
    data = pd.read_csv(filename,sep=',',encoding = 'utf-8', converters=datatype,on_bad_lines='warn')
    return data


def main():
    datalist = os.listdir('/mnt/c/Users/admin/Desktop/TASK/formldata')

    savepath = '/mnt/c/Users/admin/Desktop/TASK/'
    bar = tqdm(total=len(datalist),desc='Feature Extracting...',position=0)
    for file in datalist:
        
        f = '/'.join(['/mnt/c/Users/admin/Desktop/TASK/formldata',file])
        df = LoadData(f)

        df['jumboPayloadFlag']=df['jumboPayloadFlag'].replace(['True'],1)
        df['jumboPayloadFlag']=df['jumboPayloadFlag'].replace(['False'],0)
        df['analyResult'] = df['analyResult'].replace([2],0)
        normalized_bd, notasciistr, strlen =ByteDistribution(df['payload'])
        df['normalized_bd'] = normalized_bd
        df['notasciistr'] = notasciistr
        df['length'] = strlen
        df['payload'] = PayloadDecoding(df['payload'])

        df[['sourcePort','destinationPort','directionType','jumboPayloadFlag','packetSize','eventCount','payload','normalized_bd','notasciistr','length','analyResult']].to_csv(f'{savepath}feature/{file}',sep = ',', encoding='utf-8',index=None,escapechar='\r')
        df2 = pd.DataFrame()
        df2 = df[(df['sourcePort'] == 80) | (df['destinationPort'] == 80)]
        df2[['sourcePort','destinationPort','directionType','jumboPayloadFlag','packetSize','eventCount','payload','normalized_bd','notasciistr','length','analyResult']].to_csv(f'{savepath}port80feature/{file}',sep = ',', encoding='utf-8',index=None,escapechar='\r')
        bar.update()


    bar.close()
    
    

main() 
