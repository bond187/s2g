import requests
import sys

def acquire_solutions(CVE):
  '''
  Uses the circl org's cve search api (https://www.circl.lu/services/cve-search/) to fetch
  a json object of data. Then parse that data for the related capec, and then that capec's 
  list of solutions. Add each solution to a list, and return that list.
  '''
  try:
    r = requests.get("https://cve.circl.lu/api/cve/{}".format(CVE))
    r_json = r.json()
    #count = 1
    solutions = list()

    for item in r_json:
      if item == "capec":
        for i in range(len(r_json[item])):
          for item2 in r_json[item][i]:
            if item2 == "solutions":
              if r_json[item][i][item2] != "":
                solutions.append(r_json[item][i][item2])
                #print("{}: {}".format(count, r_json[item][i][item2]))
                #print("")
                #count = count + 1
    return solutions
  except:
    print("Error in retrieving requested CVE solution data.")
    return 1

if __name__ == "__main__":
  print(acquire_solutions(sys.argv[1]))
