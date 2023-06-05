A repository to hold work for s2g project. To run the complete task, use `python3 add_vulns_rels.py` with no argument. It will look for a file called `Solar2Grid_copy` and write to `Solar2Grid_copy2` with the updated bundle. 

It iterates over all CVEs (vulnerabilities) present in Solar2Grid bundle, finds the associated CAPEC, and then adds the Course of Action STIX objects to the bundle along with "mitigates" relationships. 
