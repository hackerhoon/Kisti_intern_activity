#!/usr/bin/python3
import pandas as pd
import numpy as np
import dask.dataframe as dd
from tqdm import tqdm
import os,time
import gc
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


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
    'jumboPayloadFlag': convert_dtype,
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
    savepath = '/mnt/c/Users/admin/Desktop/TASK/'
    mal_list = os.listdir(savepath+'malfeature')
    benign_list = os.listdir(savepath+'benignfeature')

    malcnt = 0
    bncnt = 0
    sbncnt = 0
    #snbncnt = 0
    pattern = '(\d*)_(.*)[(]'
    filelist = []
    p = re.compile(pattern) 
    #bar = tqdm(total=len(mal_list)+len(benign_list),position=0)

    for mal in mal_list:
        filelist.append(p.match(mal).group(0))
        #print(mal, benign)
        #mf = '/'.join([savepath+'malfeature',mal])
        #mdf = LoadData(mf)
        #malcnt += len(mdf)
        #print(malcnt)
        #input()
        #bar.update()
    for benign in benign_list:
        #bf = '/'.join([savepath+'benignfeature',benign])
        
        for file in filelist:
            if file in benign:
                print(file, benign)
                #bdf = LoadData(bf)
                #sbncnt += len(bdf)
                break

        #bar.update()

    #bar.close()

    print(f'length of maldata: {malcnt}, length of benign in same file {sbncnt}')

main()
