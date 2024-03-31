import random

upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
lowerCase = upperCase.lower()
digits = "12334567890"
symbols = "@#$%&*()+=/{}[]"


upper, lower, num, syms = True, True, True, True
all = ""

if upper:
	all += upperCase
if lower:
	all += lowerCase
if num:
	all += digits
if syms:
	all += symbols

length = 8
amount = 1

for x in range(amount):
	passwd = "".join(random.sample(all, length))
	print(passwd)
