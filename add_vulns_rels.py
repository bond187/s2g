import json
from cvereq import *
from stix2 import Indicator, Malware, Relationship, Bundle, CourseOfAction, Vulnerability


def create_COAs(cve_list, stig):
  #cve_list is now a list of tuples: names of cve-****-**** and their vuln id number in the stig (in order to add rels)
  '''
  TODO: Need to modify the original create_COAs() to instead of creating individual bundles, add new items to the big bundle. 
  Transform bundle into normal json (python dict), add to "objects" list (item #2 key in the dict) and then transform it back 
  into a bundle and write that to a file.
  '''
  obj = stig["objects"]

  print("Adding objects...")
  for cve in cve_list:
    #print("Adding object {} and relationships...".format(cve))
    sol_list = acquire_solutions(cve[0])
    count = 1

    for sol in sol_list:
      coa = CourseOfAction(name="coa-{}".format(count), description=sol)
      obj.append(coa)
      rel = Relationship(relationship_type='midigates', source_ref=coa.id, target_ref=cve[1])
      obj.append(rel)
      count = count + 1

  stig["objects"] = obj

#  for line in stig:
#    line.replace("'", "\"")


  print(stig)

  f = open("./Solar2Grid_copy2.json", "w")
  json.dump(stig, f)
  f.close()

#  except:
#    print("Error in parsing CVE data.")
#    return 1

#-----------------------------------------------------------


if __name__ == "__main__":
  cve_list = list()

  with open("./Solar2Grid.json",'r') as read_file:
    data = json.load(read_file)
    for i in data["objects"]:
      objects = data["objects"]
      for entry in objects:
        for key in entry:
          if key == "name" and "CVE" in entry["name"]:
            name = entry["name"] 
            id = entry["id"]
            #print(entry["name"])
            if (name,id) in cve_list:
              #print("DUPLICATE")
              continue;
            else:
              cve_list.append((name,id))
              #print(name,id)

  #Have the correct list of CVEs that appear in the solar2grid.json file in cve_list. Now we need to take that list and create 
  #coas and relationships between the cve (vulnerabilities) and the coas in the json.
    create_COAs(cve_list, data)
    print("Done! Byeee <3")


