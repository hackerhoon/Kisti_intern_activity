from datetime import datetime
import pandas as pd
import struct
import socket
import re
import time,os
import ast
from tkinter import Tk, filedialog
import tkinter as tk


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

def Hex2Byte(data): return b''.fromhex(data) # Hex type payload to bytetype Payload
    
def Bytes2String(bytestring): #bytes to string 
    
    #string = bytestring.decode('utf-8','ignore')
    string = "" 
    for c in bytestring:
        string += chr(c)        
    string_mod = re.sub("[\r\n\t]","",string) #remove \r\n\t 
    return string_mod

def Int2Ip(ip):
    try:
        ip = int(ip)
        return socket.inet_ntoa(struct.pack('>i',ip)) # >: big endian, i: int
    except:
        #Some data was NaN
        return ip 

def DecodeIp(iplist):
    outputlist = []
    for ip in iplist:
        outputlist.append(Int2Ip(ip))
    return outputlist

# this function is filtering string that was filtered by filter.txt
def Find_Tag(word,label):
    
    if label == 'User-Agent:[^\r\n]+':
        if word == 'User-agent: ViRobot Mobile Lite for Android': #this user-agent is normal
            return 0
        for bad_word in ['bot','spy','pwn','github','paros']: #you need to set this payload contents
            if bad_word in word.lower():
                return 1
    
    patt = '[.]\S+[.]?\w*'
    if label == 'filename=[^\r\n]+':
        p = re.compile(patt,re.I)
        found = p.findall(word)
        #print(found)
        if found:
            for fnd in found:
                if len(fnd) >= 6:
                    for bad_word in ['php','jsp','asp']:
                        if bad_word in fnd.lower():
                            return 1
                else:
                    for bad_word in ['php','jsp','asp']:
                        if bad_word in fnd.lower():
                            return 1

    if label in ['POST[^\r\n]+','GET[^\r\n]+']:
        if '/xmlrpc.php' in word.lower():
            return 1
        elif 'fckeditor' and 'editor' and 'filemanager' in word.lower():
            return 1
    
    return 0


def FilteringPayload(payloadlist,filterlist):

    tagging = []

    _filterlists = ['User-Agent:[^\r\n]+','POST[^\r\n]+','GET[^\r\n]+','filename=[^\r\n]+']
    used_filter = []
    for payload in payloadlist:
        tag = []

        try:
            ascii_payload = Hex2Byte(payload)
        except:
            ascii_payload = b"Error"
        
        
        for ft in filterlist:
            
            p = re.compile(bytes(ft,'utf-8'),re.I)
            if p.search(ascii_payload,re.I) is not None:
                filtered = p.findall(ascii_payload,re.I)
                for s in filtered:
                    if ft in _filterlists:
                        if Find_Tag(Bytes2String(s),ft):
                            tag.append(Bytes2String(s))
                            used_filter.append(ft)
                    else:
                        tag.append(Bytes2String(s))
                        used_filter.append(ft)
            
        
        tag = list(set(tag))
        used_filter = list(set(used_filter))
        tagging.append(tag)
   
    return tagging, used_filter


def SaveFile(dataframe,filename):
    savepath = os.path.dirname(os.path.abspath('__file__')) + '\\tagging_result'
    result_file=filename[:-4] + '_filetered.csv'
    try:
        dataframe.to_csv(savepath+'\\'+result_file,index=None,escapechar='\r')
    except PermissionError:
        print("Please close file!")
        current_time = time.strftime('%H_%M_%S', time.localtime(time.time()))
        new = result_file[:-4] + f"_new[{current_time}].csv"
        dataframe.to_csv(savepath+'\\'+new,index=None,escapechar='\r')

def LoadFile(f):

    datatype = {
    '_id' : convert_dtype,
    'sourceIP': convert_int,
    'sourcePort': convert_int,
    'destinationIP': convert_int,
    'destinationPort': convert_int,
    'directionType': convert_int,
    'protocol': convert_int,
    'analyResult': convert_int,
    'payload': convert_dtype,
    'payload_ascii' : convert_dtype
    }

    try:
        if f[-3:] == 'txt':
            data = pd.read_csv(f,sep='\t',encoding = 'utf-8',on_bad_lines='skip', converters=datatype)
        elif f[-3:] == 'csv':
            data = pd.read_csv(f,sep=',',encoding = 'utf-8',on_bad_lines='skip', converters=datatype)
    except:
        try:
            if f[-3:] == 'txt':
                data = pd.read_csv(f,sep='\t',encoding = 'cp949',on_bad_lines='skip', converters=datatype)
            elif f[-3:] == 'csv':
                data = pd.read_csv(f,sep=',',encoding = 'cp949',on_bad_lines='skip', converters=datatype)
        except:
            if f[-3:] == 'txt':
                data = pd.read_csv(f,sep='\t',encoding = "ISO-8859-1",on_bad_lines='skip', converters=datatype)
            elif f[-3:] == 'csv':
                data = pd.read_csv(f,sep=',',encoding = "ISO-8859-1",on_bad_lines='skip', converters=datatype)

    return data

def ReadIpBlacklist():

    path = os.path.dirname(os.path.abspath('__file__')) +'\\ipblacklist'
    filelist = os.listdir(path)
    malware_ip_list = []
    
    for file in filelist:
        f = '/'.join([path,file])
        df = pd.read_csv(f,sep=',',encoding = 'utf-8',on_bad_lines='skip')
        malware_ip_list += df['IP'].tolist()

    return malware_ip_list

def ReadRegexString():

    f = open('filter.txt','r')
    read = f.read()
    arr = ast.literal_eval(read)

    return arr

def MakeFileList(extension_list, dirpath):
    root = os.path.dirname(os.path.abspath(dirpath))
    datalist = []
    for path, dirs, files in os.walk(root):        
        dir_path = os.path.join(root, path)
        for file in files:
            if file[-3:] in extension_list:
                datalist.append(os.path.join(dir_path, file))

    return datalist



def SelectFileList():
    extension = ['txt']
    root = Tk()
    root.wm_withdraw()
    root.dirName = filedialog.askdirectory(parent=root, initialdir="/", title='Select Directory')
    root.destroy()
    root.mainloop()
    
    filelist = MakeFileList(extension, root.dirName)

    return filelist

def main():
    
    file_list = SelectFileList()

    malip = ReadIpBlacklist()

    Regexstrlist = ReadRegexString()    

    for i, file_ in enumerate(file_list, start=1):
        print(f'[{datetime.now()}] Start {file_} load...')
        data = LoadFile(file_)
        data['sourceIP'] = DecodeIp(data['sourceIP'])
        data['destinationIP'] = DecodeIp(data['destinationIP'])
        tagging, used_filter = FilteringPayload(data['payload'],Regexstrlist)
        print(f'[{datetime.now()}] filtering by {used_filter}...')
        for i,(sip,dip) in enumerate(zip(data['sourceIP'].tolist(),data['destinationIP'].tolist())):
            if sip in malip:
                tagging[i].append(sip)
            if dip in malip:
                tagging[i].append(dip)
        string = []
        for k in range(len(tagging)):
            string.append('{string: '+', '.join(tagging[k])+'}')

        data['tagging'] = string
        data.drop(labels='payload_ascii',axis=1, inplace = True)
        SaveFile(data,file_.split('\\')[-1]) # this .py file using in window os

main()

###### This python code for auto tagging using in XAI learning data ##############################################################
#
#   Code follows under explaination.
#   1. Select directory that filelist is in 
#   2. Load filelist
#   3. Find malicious clue in payload file by file
#   4. Check IP's reliability using collected unreliable IP set at IP scoring sites (malware.com, virustotal, ipscore....)
#   5. Write the checked contents in new filtered file
#   6. Save the files
#
###################################################################################################################################





