from stix2 import Indicator, Malware, Relationship, Bundle, CourseOfAction, Vulnerability
from cvereq import *
import sys
import os
import json

def create_COAs(CVE):
  '''
  Fetch a list of solutions with acquire_solutions(). Then iterate over the solutions
  and create a STIX CourseOfAction SDO for each. Create and return a bundle of COAs.
  Also writes that bundle to a json file in the coa/ directory.
  TODO: names are not meaningful, and I'm not sure how to set a name from description.
  '''
  sol_list = acquire_solutions(CVE)
  vuln = Vulnerability(name= CVE, description="placeholder")
  coas = [vuln]
  count = 1

#  try:
  for sol in sol_list:
    coa = CourseOfAction(name="coa-{}".format(count), description=sol)
    coas.append(coa)
    coas.append(Relationship(relationship_type='midigates', source_ref=coa.id, target_ref=vuln.id))
    count = count + 1

    #print(coas)
    
  bundle = Bundle(coas)
  bundledict = dict(bundle) 

    #bundledict
    #Write bundle for single CVE to a file
  f = open("./coa/{}-COA-bundle.json".format(CVE), "w")
  f.write(str(bundle)) 
  f.close()
  return bundle #.serialize(pretty=True)
#  except:
#    print("Error in parsing CVE data.")
#    return 1

if __name__ == "__main__":
  create_COAs(sys.argv[1])













'''
indicator = Indicator(name="File hash for malware variant",
                      pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                      pattern_type="stix")

malware = Malware(name="Poison Ivy",
                  is_family=False)

relationship = Relationship(relationship_type='indicates',
                            source_ref=indicator.id,
                            target_ref=malware.id)

coa = CourseOfAction(name="Write better code",
                     description="The developer who wrote this needs to fix it, or better yet, travel back in time and stop her younger self before the mistake was made.")
 

relationship1 = Relationship(relationship_type='mitigates',
                            source_ref=coa.id,
                            target_ref=malware.id)

#OR for better readibility we can declare a relationship in a more natural source --> target way.

#relationship = Relationship(indicator, 'indicates', malware)

bundle = Bundle(indicator, malware, coa, relationship, relationship1)

#print(indicator.serialize(pretty=True))
#print(malware.serialize(pretty=True))
#print(relationship.serialize(pretty=True))

print(bundle.serialize(pretty=True))

'''
