#-*- coding:utf-8 -*-
import string

_ascii = "abcdefghijklmnopqrstuvwxyz0123456789"
out_f = open('word_list.txt', 'w')
for i1 in _ascii:
    print(i1)
    for i2 in _ascii:
        for i3 in _ascii:
            for i4 in _ascii:
                for i5 in _ascii:
                    tmp = i1+i2+i3+i4+i5+"\n"
                    out_f.writelines(tmp)
out_f.close()