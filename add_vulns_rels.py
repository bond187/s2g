import json
from cvereq import *
from stix2 import Indicator, Relationship, Bundle, CourseOfAction, Vulnerability


def create_add_COAs(cve_list, stig):
  '''
  Takes a list of MITRE CVE-****-**** format strings and a stig bundle as arguments. It iterates over the list, gets the list of 
  solutions provided by `acquire_solutions()`, and adds these solutions as COA stix objects, along with mitigates relationships,
  to the objects entry in the stig bundle. It then writes the entire bundle to a new file. Currently it is hardcoded to only
  read from `Solar2Grid_copy.json` and write to `Solar2Grid_copy2.json` files that must be in the same directory, but an argument
  could be added to read and write anywhere.
  '''
  obj = stig["objects"]
  print("Adding objects...")

  for cve in cve_list:
    print("Adding object {} and relationships...".format(cve))
    sol_list = acquire_solutions(cve[0])
    count = 1

    for sol in sol_list:
      coa = CourseOfAction(name="coa-{}".format(count), description=sol)
      obj.append(json.loads(coa.serialize()))
      rel = Relationship(relationship_type='midigates', source_ref=coa.id, target_ref=cve[1])
      obj.append(json.loads(rel.serialize()))
      count = count + 1

  stig["objects"] = obj

  with open("./Solar2Grid_copy2.json", "w") as w_file:
    json.dump(stig, w_file, indent=4)

#-----------------------------------------------------------

def get_cve_list(file):
  '''
  This function reads through a stig bundle and finds all instances of objects with a name that includes "CVE". It puts all these
  names into a list and returns it.
  '''
  with open("./{}".format(file),'r') as read_file:
    cve_list = list()
    data = json.load(read_file)
    for i in data["objects"]:
      objects = data["objects"]
      for entry in objects:
        for key in entry:
          if key == "name" and "CVE" in entry["name"]:
            name = entry["name"] 
            id = entry["id"]
            if (name,id) in cve_list:
              continue;
            else:
              cve_list.append((name,id))
  return cve_list

if __name__ == "__main__":
  cve_list = get_cve_list("Solar2Grid_copy.json")

  with open("./Solar2Grid_copy.json", 'r') as file:
    data = json.load(file)
    create_add_COAs(cve_list, data)
    print("Done! Bye!")


