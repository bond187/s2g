import json
from coa_vuln import *

cve_list = list()

with open("./Solar2Grid.json",'r') as read_file:
  data = json.load(read_file) 
  for i in data["objects"]:
    objects = data["objects"]
    for entry in objects:
      for key in entry:
        if key == "name" and "CVE" in entry["name"]:
          #print(entry["name"])
          if entry["name"] in cve_list:
            print("DUPLICATE")
          else:
            cve_list.append(entry["name"])

count = 1
for item in cve_list:
  print("{} : {}".format(count,item))
  count += 1
'''
for cve in cve_list:
  print("Creating file for {}".format(cve))
  create_COAs(cve)
'''
