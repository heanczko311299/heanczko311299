#!/usr/bin/env python3


listRem = "\\x00\\x23\\x3c\\x83\\xba".split("\\x")
for x in range(1, 256):
    if "{:02x}".format(x) not in listRem:
        print("\\x" + "{:02x}".format(x), end='')
print()
