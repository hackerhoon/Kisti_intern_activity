#!/usr/bin/python3

from matplotlib import pyplot as plt
import pandas as pd
import os
import numpy as np

dirpath =['.\\benignanal','.\\malanal']
filelist = os.listdir(dirpath[0])



i = 0

for file in filelist:
    if 'IP' not in file:
        print(file)
        
        f = '\\'.join([dirpath[0],file])
        f2 = '\\'.join([dirpath[1],file])
        df = pd.read_csv(f, sep=',', encoding = 'utf-8',error_bad_lines=False, warn_bad_lines=True)
        df2 = pd.read_csv(f2, sep=',', encoding = 'utf-8',error_bad_lines=False, warn_bad_lines=True)
        keylist = df.columns.tolist()
        x = df[keylist[0]].tolist()
        x2 = df2[keylist[0]].tolist()
        len_x = len(x)
        
        if len_x < 10:
            x = x[:len_x]
            x2 = x2[:len_x]
            y =[round(100 * i/sum(df[keylist[1]].tolist()),2) for i in df[keylist[1]].tolist()[:len_x]]
            y2 =[round(100 * i/sum(df2[keylist[1]].tolist()),2) for i in df2[keylist[1]].tolist()[:len_x]]
        else:
            x = x[:20]
            x2 = x2[:20]
            y =[round(100 * i/sum(df[keylist[1]].tolist()),2) for i in df[keylist[1]].tolist()[:10]]
            y2 =[round(100 * i/sum(df2[keylist[1]].tolist()),2) for i in df2[keylist[1]].tolist()[:10]]
        #print(x,y)
        #input()
        total_percent = round(100 * sum(df[keylist[1]].tolist()[:20])/sum(df[keylist[1]].tolist()),2)
        total_percent2 = round(100 * sum(df2[keylist[1]].tolist()[:20])/sum(df2[keylist[1]].tolist()),2)
        plt.figure(i)
        i+=1
        plt.title(file+f', benign: {total_percent}, malware: {total_percent2} of total')
        x = [str(k) for k in x]
        x2 = [str(k) for k in x2]
        x_ = list(set(x+x2))
        plt.bar(x,y,color='b')
        plt.bar(x2,y2,color='r')
        plt.legend()
        y_ = y+y2
        arange = np.arange(0,len(x_),1)
        plt.xticks(arange)
        plt.yticks(np.arange(0,100,step =20))
        for j in range(len(x)):
            height = y[j]
            plt.text(x[j],height+0.25,f'{x[j]}[{height}]', ha = 'center',va ='bottom', size = 7,color = 'blue')

        for j in range(len(x2)):
            height = y2[j]
            if int(height) - int(y[j]) < 2:
                height+=2
            plt.text(x2[j],height+0.25,f'{x2[j]}[{height}]', ha = 'center',va ='bottom', size = 7, color = 'red')
        #plt.savefig('.\\pictures\\'+file[:-3]+'png')
        
    else:
        continue

plt.show()

