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
path = '/mnt/c/Users/master/Desktop/jupyter/z/tagging/tagging_data_modified'

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
        ip = 0
    return socket.inet_ntoa(struct.pack('>i',ip)) # >: big endian, i: int

def SetIpList(ip_list,ip_set):
    count = 0
    ip_len = len(ip_set)
    for ip in ip_list:
        ip = Int2Ip(ip)
        if ip not in ip_set:
            ip_set.append(ip)
            count += 1
    print(f"### {count} ip is added to {ip_len} ip_set ###")

def CreateIpStats(ip_list,ip_dict):
    stats = []
    for ip in ip_list:
        ip = Int2Ip(ip)
        stats.append(ip_dict[ip])
    return stats

def Read_Data_Csv(file_path,sep=','):
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

def LoadIplist(path, ip_set):
    file_list = os.listdir(path)
    count = 0
    for f in file_list:
        count += 1
        file_path = path + '/'+ f
        try:
            if f[-3:] == 'txt':
                data = pd.read_csv(file_path, sep = '\t', encoding = 'utf-8')
            elif f[-3:]== 'csv':
                data = pd.read_csv(file_path, sep = ',', encoding = 'utf-8')
        except:
            try:
                data = pd.read_csv(file_path, sep = '\t', encoding ='CP949')
            except:
                if f[-3:] == 'csv':
                    data = Read_Data_Csv(file_path)   
                elif f[-3:] == 'txt':
                    data = Read_Data_Csv(file_path,'\t')
                    
        ipdf = data[['sourceIP', 'destinationIP']]
        print(f"\nSet {count}st IP list, File: {f}")
        SetIpList(ipdf['sourceIP'],ip_set)
        SetIpList(ipdf['destinationIP'],ip_set)



def Iplist2Csv(filename1, filename2, ip_set,next_idx):
    print("Write IP list to csv file and Index.txt....")
    list_df = pd.DataFrame({
        "IP": ip_set
    })
    list_df.to_csv(filename1, index = None)
    f = open(filename2,"w")
    f.write(str(next_idx))
    f.close()

def Ipdict2Csv(filename, ip_dict):
    print("Write IP dict to csv file....")
    dict_df = pd.DataFrame(list(ip_dict.items()), columns = ['IP','Detected_Url_Total'])
    dict_df.to_csv(filename, index = None)

def Csv2Iplist(filename1,filename2):
    print(f"Read IP list in csv file and Index.txt....")
    try:
        data = pd.read_csv(filename1)
        df = data[['IP']] 
        ip_set = df['IP'].tolist()
        print("### Read IP success! ###")
        try:
            f = open(filename2,'r')
            next_idx = int(f.read())
        except FileNotFoundError:
            next_idx = 0
        print(f"Next Index is {next_idx}\n\n")
    except FileNotFoundError:
        ip_set = []       
        next_idx = 0
    
    return ip_set,next_idx

def Csv2Ipdict(filename):
    try:
        dataDf = pd.read_csv(filename)
        dataDict = dataDf.to_dict('split')
        ip_dict = dict(dataDict['data'])
    except FileNotFoundError:
        ip_dict = {}

    return ip_dict

#check ip at malwares.com
#dict 업데이트는 천천히...
def IpScan(ip_set,ip_dict,next_idx,api_key,max2find):
    count = 0
    cant_find = 0
    for ip in ip_set:
        printProgressBar(count,3000,"finding malicious ip")
        params = {'api_key': api_key, 'ip': ip}
        if count < max2find:
            #print(ip)
            if ip not in ip_dict or ip_dict[ip] == -1:
                #print('find')
                try:
                    response = requests.get('https://public.api.malwares.com/v3/ip/info', params=params,verify =False)   
                    ip_dict[ip] = response.json()["detected_url"]['total']
                except:
                    ip_dict[ip] = -1
                count = count + 1
            else:
                continue
        elif count == max2find:
            break
        else:
            ip_dict[ip] = -1
        
        
    print(f'\ncan not found {cant_find}s ip')
    next_idx += max2find
    return next_idx


#check ip at virustotal
def VT_IpScan(ip_set,ip_dict,next_idx,params):
    count = 0
    max_request = 500
    len_ip = len(ip_set)
    for cnt,ip in enumerate(ip_set):
        if count < max_request:
            if ip not in ip_dict:  # 문자열로 읽어옵니다..
                try:
                    response = requests.request("GET", url+ip, headers=params,verify = False)
                    #print(response.json())
                    #last_analysis_stats:{"harmless": 0,"malicious": 0,"suspicious": 0,"timeout": 0,"undetected": 0}
                    ip_dict[ip] = response.json()['data']['attributes']["last_analysis_stats"]
                except:
                    ip_dict[ip] = -1
                count = count + 1
                if response.status_code != 200:
                    print("response error\n")
                    break
                if count%4 == 0 and count < 500:
                    time.sleep(61)
                    
            elif ip_dict[ip] == '-1':
                try:
                    response = requests.request("GET", url+ip, headers=params,verify = False)
                    #print(response.json())
                    #last_analysis_stats:{"harmless": 0,"malicious": 0,"suspicious": 0,"timeout": 0,"undetected": 0}
                    ip_dict[ip] = response.json()['data']['attributes']["last_analysis_stats"]
                except:
                    ip_dict[ip] = -1
                count = count + 1
                if response.status_code != 200:
                    break
                if count%4 == 0 and count <500:
                    time.sleep(61)

        else:
            ip_dict[ip] = -1 
        printProgressBar(cnt,len_ip,"check ip")
    next_idx += count
    return next_idx
        
def menu():
    print("### choose mode ###")
    print("1: IP scan at malwares.com")
    print("2: IP scan at virustotal")
    print('0: exit')
    return int(input('input mode: '))

def open_ip_file():
    print('Load IP list, Index, IP_dict')
    Iplistfile = WriteFileName("Input ip list filename(ex. IP_list, file format is .csv): ",0)
    Indexfile = WriteFileName("Input Index filename(ex. index, file format is .txt): ",1)
    Ipdictfile = WriteFileName("Input ip dict filename(ex. IP_dict, file format is .csv): ",0)
    return Iplistfile, Indexfile, Ipdictfile

def WriteFileName(printed_string,idx):
    while True:
        EXTENTIONS = ('csv','txt')
        filename = '.'.join([input(printed_string),EXTENTIONS[idx]])
        file_ext = filename.split('.')[-1]
        if file_ext != EXTENTIONS[idx]:
            print(f'Error: {filename} is not proper format!')
        else:
            break    
    return filename


def main():

    Iplistfile, Indexfile, Ipdictfile = open_ip_file()
    ip_set, next_idx = Csv2Iplist(Iplistfile,Indexfile)
    ip_dict = Csv2Ipdict(Ipdictfile)
    if len(ip_set) == 0:
        LoadIplist(path,ip_set)
    
    a = menu()
    if a == 1:
        next_idx = IpScan(ip_set, ip_dict, next_idx, myapi_key,3000)
        Iplist2Csv(Iplistfile, Indexfile ,ip_set ,next_idx)
        Ipdict2Csv(Ipdictfile,ip_dict)
    elif a == 2:
        next_idx = VT_IpScan(ip_set, ip_dict, next_idx,vt_params)
        Iplist2Csv(Iplistfile, Indexfile ,ip_set ,next_idx)
        Ipdict2Csv(Ipdictfile,ip_dict)
    elif a == 0:
        print("EXIT!")
        exit(0)

main()     