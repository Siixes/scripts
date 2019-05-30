"""
Title: checkProcs.py
Author: Kyle
Description: this is a quick and dirty script used to dump all of the processes from a RAM capture, hash them, and submit the hashes to VirusTotal to see if there are any hits
this is built to use a private VirusTotal api key which is limited to 4 queries per minute, feel free to substitute your own. 
if your key is not limited to 4/minute, feel free to delete "time.sleep(15)" in main() to speed that part up
Usage: python checkProcs.py -p <Volatility profile> -l <path to volatility> -f <path to RAM capture>
"""

from subprocess import call
import os
import argparse
import hashlib
import glob
import time
import urllib
import urllib2
import json as simplejson

def callPsList(args):
	# receives the necessary args and uses them to call Volatility's pslist plugin
	returnCode = call("%s -f %s --profile=%s pslist > %s" % (args.volPath, args.imagePath, args.profile, args.psOutput), shell=True)
	return returnCode 

def md5(fname):
	# used to calculate the md5 of a file
	md5 = hashlib.md5()
	with open(fname) as f:
		for chunk in iter(lambda: f.read(4096), ""):
			md5.update(chunk)
	return md5.hexdigest()

def dumpProcesses(args):
	pids = []
	# first we need to make sure our dump directory is created
	if not os.path.isdir(args.dumpDir):   # if it doesn't already exist
		returnCode = call("mkdir %s" % (args.dumpDir), shell=True)
		# check to make sure the call completed successfully
		if (returnCode != 0):
			print "[-] Error making dump directory"
			return 2
	# now that we have our dump directory, parse through pslist to grab all pids, and dump them with Volatility
	for line in open(args.psOutput):
		if (('Offset' in line) or ('---' in line)):
			pass
		else:
			pid = line.split()[2]
			pids.append(pid)
	for pid in pids:
		print "[*] Working on %s" % (pid)
		ret = call("%s -f %s --profile=%s memdump -p %s -D %s" % (args.volPath, args.imagePath, args.profile, pid, args.dumpDir), shell=True)
	print "[+] Finished dumping files"
	
def md5Processes(args):
	# now md5sum all our dumped processes
	# create a file with md5s for future reference if necessary
	outfile = open('processMD5s.txt', 'w')
	hashes = []
	for entry in glob.glob(args.dumpDir+"/*"):
		if os.path.isfile(entry):
			print "[*] Creating md5 for %s" % (entry)
			md5hash = md5(entry)
			hashes.append(md5hash)
			outfile.write("%s - %s\n" % (entry, md5hash))
	outfile.close()
	return hashes
		

def lookupHash(md5):
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	# enter your creds below
	parameters = {"resource": md5, "apikey": "<insert api key here>"}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	response_dict = simplejson.loads(json)
	toot = response_dict.get("positives")
	# check to see if the hash was found in the VT data set
	if str(toot) == "None":
		return "[-] %s not found in the VirusTotal dataset." % (md5)
	elif toot == 0:
		return "[-] %s found in the VirusTotal data set with 0 positives." % (md5)
	else:
		results = ""
		results += "Results for %s\n" % (md5)
		for field in response_dict:
			if field == 'positives':
				results += "Positives: %i\n" % (response_dict[field])
			if field == 'total':
				results += "Total AVs: %i\n" % (response_dict[field])
			if field == 'scans':
				for av in response_dict[field]:
					if response_dict[field][av]['detected']:
						results += "%s\t%s\n" (av, response_dict[field][av]['result'])
		return results

def main(args):
	outfile = open(args.vtOutput, 'w')
	i = 1                   
	# first thing we'll do is run the pslist plugin from Volatility
	returnCode = callPsList(args)
	# if there was an error calling pslist in Volatility, return an error
	if (returnCode != 0):
		print "[-] There was an error running Volatility's pslist on the RAM image"
		return 1
	# then open up the pslist results, parse out processId's, and use Volatility to dump them all out
	dumpProcesses(args)
	# once processes are dumped, get a list of all of their md5s
	hashes = md5Processes(args)
	# now that we have the hashes, look them up in VirusTotal and write output to a file
	for entry in hashes:
		print "Working on hash %i of %i (%s)" % (i, len(hashes), entry)
		result = lookupHash(entry)
		outfile.write("%s\n" % (result))
		i += 1
		# if you're using a generic private key sleep for 15 seconds between each call to VirusTotal
		time.sleep(15)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--profile", dest='profile', help="Profile for Volatility to use")
	parser.add_argument("-l", "--volPath", dest='volPath', help="Path to volatility")
	parser.add_argument("-f", "--file", dest='imagePath', help="Path to RAM capture")
	parser.add_argument("-s", "--psFile", dest='psOutput', default='pslist.txt', help="Path to output file holding the results of Volatility's pslist plugin")
	parser.add_argument("-t", "--vtFile", dest='vtOutput', default='vtOutput.txt', help="Path to output file hold results of VirusTotal lookups")
	parser.add_argument("-d", "--dump", dest='dumpDir', default='dump', help="Directory to dump the binaries")
	args = parser.parse_args()
	# as long as the user enter valid file paths, we'll continue
	# warning, this script does not confirm that the user actually entered the path to Volatility and a RAM image, so input is untrusted
	if (os.path.isfile(args.volPath) and os.path.isfile(args.imagePath) and (args.profile)):
		main(args)
	else:
		print "[-] Error: something went wrong parsing your inputs. :("
