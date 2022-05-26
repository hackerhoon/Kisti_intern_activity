#!/usr/bin/python3
import ast 
f = open('filter.txt','r')

read = f.read()
print(read)
arr = ast.literal_eval(read)
print(arr[0])



#f.write(str(filter_list))

#f.close()
