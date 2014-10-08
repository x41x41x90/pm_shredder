#!/usr/bin/env python
import os
i = 0
j = 0
while i <= 255:
	while j <= 255:
		x = str(hex(i)).replace("0x", "") 
		y = str(hex(j)).replace("0x", "")
		if len(x) == 1: x = "0" + x
		if len(y) == 1: y = "0" + y
		os.system("mkdir -p clarity/" + x + "/" + y)
		j+=1
	j = 0
	i+=1