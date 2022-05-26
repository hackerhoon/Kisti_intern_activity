#!/usr/bin/python3
import sys
import os
import pandas as pd
import struct
import socket
import requests
import json
import csv
import time
import collections

url = 'https://www.virustotal.com/api/v3/ip_addresses/'
#vt_api_key = '9429049607b5c272d426922a7d8e9346a914454e4df545764aa012e53c9d3bfc'
vt_api_key ='ddd3f87fd66047e8dfe27290c7b1c82ca2f2131343718aece81653a604d9ea70'
vt_params = {
    "Accept": "application/json",
    "x-apikey": vt_api_key
}
api_key =  '4254D4189D7BFBF7FF69B2804A6998CA147428812C2B75C328AF322686D0F632' # kisti api key
myapi_key = '09AA0F29EBD74FECFA3543C9B23798BA0E25159439CCA7A20A19ED289F591B03'
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def printProgressBar(i,max,postText):
    n_bar = 20 #size of progress bar
    j = i/max
    sys.stdout.write('\r')
    sys.stdout.write(f"[{'=' * int(n_bar * j):{n_bar}s}] {int(100 * j)}%  {postText}")
    sys.stdout.flush()

def Int2Ip(i_data):
    try:
        ip = int(i_data)
    except:
        try:
            ip = int(float(i_data))
        except:
            ip = 0
    return socket.inet_ntoa(struct.pack('>i',ip)) # >: big endian, i: int

def Read_Csv(file_path,sep=','):
    f = open(file_path,'r')
    rdr = csv.reader(f,delimiter = sep)
    next(rdr)
    id_ = []
    srcip = []
    srcport = []
    dstip = []
    dstport = []
    directionType = []
    protocol = []
    detectName = []
    analyResult = []
    payload = []
    payload_ascii = []

    for line in rdr:
        id_.append(line[0])
        srcip.append(line[1])
        srcport.append(line[2])
        dstip.append(line[3])
        dstport.append(line[4])
        directionType.append(line[5])
        protocol.append(line[6])
        detectName.append(line[7])
        analyResult.append(line[8])
        payload.append(line[9])
        payload_ascii.append(line[10])
    data = pd.DataFrame({
        '_id': id_,
        'sourceIP': srcip,
        'sourcePort': srcport,
        'destinationIP': dstip,
        'destinationPort': dstport,
        'directionType': directionType,
        'protocol': protocol,
        'detectName': detectName,
        'analyResult': analyResult,
        'payload': payload,
        'payload_ascii': payload_ascii
    })

    return data

def LoadFile(f):
    try:
        if f[-3:] == 'txt':
            data = pd.read_csv(f,sep='\t',encoding = 'utf-8')
        elif f[-3:] == 'csv':
            data = pd.read_csv(f,sep=',',encoding = 'utf-8')
    except:
        try:
            if f[-3:] == 'txt':
                data = pd.read_csv(f,sep='\t',encoding = 'cp949')
            elif f[-3:] == 'csv':
                data = pd.read_csv(f,sep=',',encoding = 'cp949')
        except:
            try:
                data = Read_Csv(f)
            except:
                data = Read_Csv(f,'\t')
    return data


path = '/mnt/c/Users/master/Desktop/jupyter/z/tagging/tagging_data_modified'

def main():
    file_list = os.listdir(path)
    mipset = []
    c=0
    for f in file_list:
        file_path = path + '/'+ f
        data = LoadFile(file_path)
        srcCount = collections.Counter(data['sourceIP'].tolist())
        dstCount = collections.Counter(data['destinationIP'].tolist())
        mipset += list(dict(srcCount).keys())[10:100] #choice top 10
        mipset += list(dict(dstCount).keys())[10:100]
        printProgressBar(c,69,'read file')
        #print(mipset)
        c+=1
    mipset = list(set(mipset))
    IPs = [Int2Ip(ip) for ip in mipset]
    savedf = pd.DataFrame({'IP': IPs})
    savedf.to_csv('MostIPs2.csv',sep = ',',index=None)

   
main()     