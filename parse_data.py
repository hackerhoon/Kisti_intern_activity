#!/usr/bin/python3
import pandas as pd
import struct
import socket
import requests
import urllib3
import json
import re
import csv
import chardet
import sys,time



def Hex2Ascii(data):
    #return value type is bytes
    return b''.fromhex(data)
    
def printProgressBar(i,max_,postText):
    n_bar = 20 #size of progress bar
    j = i/max_
    #sys.stdout.write('\r')
    sys.stdout.write(f"\r[{'=' * int(n_bar * j):{n_bar}s}] {int(100 * j)}%  {postText}")
    sys.stdout.flush()

def DecodeList(list_):
    #decode list 'utf-8' 

    s = []     
    for i in list_:
        try:
            s.append(str(i,'utf-8')) 
        except:
            s1_ = ""
            for j in i:
                    if j == '\r':
                        j=''
                    elif j =='\n':
                        j=''
                    s1_ += chr(j)
            s.append(s1_)
    filtered_list = s
    filtered_list = list(set(filtered_list))
    filtered_list.sort()
    return filtered_list

def CreateBytesPattern(filter_list):
    pat = ''
    for f in filter_list:
        pat += f +'|'
    return bytes(pat[:-1],'utf-8')

def List2Tag(filtered):
    tag = []
    n = []
    sub_pat = '[.].*$'

    bot4jce = 'user-agent: bot/0.1 (bot for jce)'
    misterspy = 'mister spy'

    if bot4jce in filtered:
        string = "{string: USER-AGENT: BOT/0.1 (BOT FOR JCE)}"
        return string

    if misterspy in filtered:
        string = "{string: Mister SPY}"
        return string 


    if len(filtered) == 1:
        if "filename" in filtered[0]:
            p = re.compile(sub_pat)
            found = p.findall(filtered[0])
            s = ' '.join(found)
            n.append(s)
            string = "{" +f"string: {n}"+"}"
            return string 

    
    for e in filtered:
        if "filename" in e:
            p = re.compile(sub_pat)
            found = p.findall(e)
            if found:
                n.append(found[0])
        
    if n != []:
        n = list(set(n))
        string = "{" +f"string: {n}"+"}"
        return string

    string = "nothing"
    return string


def FilteringPayload(payloadlist):
    ret = {}
    payload_to_ascii = []
    filtered_payload = []
    filtered_payload_len = [] 
    tagging = []
    count = 0
    
    filter_list = ['User-Agent:[^\r\n]+','Mister\sSpy','POST\s[^\r\n]+','filename=[^\r\n]+','GET\s[^\r\n]+','<[?]php[\s\S]*[?]?>?']
    #filter_list = ['<[?%][\r\n]?.*[>]?']
    pat = CreateBytesPattern(filter_list)
    max_count = len(payloadlist)
    for payload in payloadlist:
        
        s = Hex2Ascii(payload)
        payload_to_ascii.append(s)
        p = re.compile(pat,re.I)
        filtered_list = p.findall(s)
        filtered_list = DecodeList(filtered_list)

        tagging.append(List2Tag(filtered_list))

        if filtered_list:
            filtered_payload.append(str(filtered_list))
            filtered_payload_len.append(len(filtered_list))
        else:
            filtered_payload.append("not matched")
            filtered_payload_len.append(0)

        count += 1
        printProgressBar(count,max_count,"Filtering")

    ret['payload_to_ascii'] = payload_to_ascii
    ret['filtered_payload'] = filtered_payload
    ret['filtered_payload_len'] = filtered_payload_len
    ret['tagging'] = tagging

    return ret

path = '/mnt/c/Users/master/packet_analysis'
filename = '2204_WEB-PAT-00-00-file(upload).05102701@.txt'
fullpath = path + '/' +filename 
data = pd.read_csv(fullpath,sep = "\t")

df = data[['detectName', 'analyResult', 'payload']]

df = df.copy() #무조건 있어야함 에러남!

result = FilteringPayload(df['payload'])

df["payload_to_ascii"] = result['payload_to_ascii']
df["filtered_payload"] = result['filtered_payload']
df["filtered_len"] = result['filtered_payload_len']
df['tagging'] = result['tagging']

print("\nWrite filtered file....")
result_file=filename[:-4] + '_filetered.csv'
try:
    df.to_csv(result_file,index=None,escapechar='\r')
except PermissionError:
    print("Please close file!")
    current_time = time.strftime('%H_%M_%S', time.localtime(time.time()))
    new = result_file[:-4] + f"_new[{current_time}].csv"
    df.to_csv(new,index=None,escapechar='\r')
print("Done!")
