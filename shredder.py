#!/usr/bin/env python
'''
LICENSING
This code is licensed under the Creative Commons Attribution-NonCommercial 2.5 Generic licensing. 
You can read more about the licensing here: http://creativecommons.org/licenses/by-nc/2.5/

File: shredder.py
Implementation: Used as "cat email.eml | ./shredder.py <randomValForDebugging>"
Functions: "shred" an email into each part using email lib, scanning each part, and 
manipulating them.
 - Rips links out of ALL email pieces
 - "Cleans" links to be fed into SEIM tool
 - Runs Yara on each piece of the email. 
 - Performs a check and runs Attachment set of rules vs. non-attachment set of rules
   * IMPORTANT! In previous testing, this leads to ~50% overall faster processing
 - Pulls out email meta data (think NSA)
 - Can get back to original email for each piece
Extra dependancies: Yara, Yara-python, ssdeep (to keep it sleek and sexy, not dependancy hell)
'''

vtApi = "0xdead1337b33f" # Virustotal API key

import sys, email, uuid, hashlib, base64, json, time # basic functions. sys == args, email == basic email processing, uuid == random tracking key, hashlib == sha256 + MD5 support, base64 == for finiky base64 blobs, json == json, time == time
import quopri # This is used for emails that have funky formatted text, such as =20 for a space. THIS IS NEEDED AND IMPORTANT, or things break / doesn't get all the way processed!!!
import yara # This is for using the Yara engine. Important, as none of this would be possible. 
import re # regex for links
import ssdeep # for fuzzy hashes // TEMPORARILY REMOVED
import sqlite3 # for database
import urllib, urllib2 # For Virustotal 
import os
my_uuid = str(uuid.uuid4()) # Creates the unique hash at runtime. This is used for tracking back the email

awesome_s_check = 1
outFile = "outFile.csv"

conn = sqlite3.connect("clarityData") # name of DB
my_db = conn.cursor()

# For debugging. If it's ./shredder.py asdfasdfasdfagagasdf, debugging is set and output will commence.
vtCheck = 0
if len(sys.argv) >1:
	debug = 1
else:
	debug = 0

# if the attachment returns back as "attachment.zip", with quotes, it must be cleaned. 
def clean_attachment_name(att):
	att = att[att.find("\"")+1:]
	att = att[:att.find("\"")]
	return att

# If email addresses come back like <user@example.com>, the ><'s must be cleaned, as this is not DB friendly / SEIM friendly
def clean_addresses(names):
	i = 0
	for each in names:
		each = each[each.find("<")+1:]
		each = each[:each.find(">")]
		names[i] = each
		i+=1
	return names

# This is for grabbing the message= from the meta data field from the Yara rule.
# *** IMPORTANT !!!
def mycallback(data):
	#if data["matches"] == True:
	#	user_message.append(data["meta"]["message"])
	yara.CALLBACK_CONTINUE

# This is for pulling out all links from an email. This can be extended to include ftp[s] as well, but 
# should be good as-is. I suck at regex, so if you have a more efficient way to do this...leme know. 

def extract_my_links(data):
	links = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)
	return links

# Cleans e's. It's best to blast them all here at the end than having it in regex routine. Again...killed servers. 
# Reasoning: can be fed through SEIM / Splunk / custom API instead of http://foo.bar.evil.com/bleh.exe, and can just 
# look for foo.bar.evil.com . 
def clean_url(url):
	url = url.replace("http://", "").replace("https://", "")
	if url.find("/") != -1:
		return url[:url.find("/")] # Cleans it out to TLD's
	else:
		return url

def virustotalApi(hashes):
	if vtCheck == 1:
		temp = ""
		for each in hashes:
			temp +=each + ", "
		temp = temp[:-2]
		url = "https://www.virustotal.com/vtapi/v2/file/rescan"
		parameters = {"resource": temp, "apikey": vtApi}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		return response.read()
	else:
		return ""

'''
Need a big comment field for this one. =D

This is the routine that does the magic. First, the email needs to be cleaned with qupori (further down) 
then fed to email walk. Once walking, the pieces of the email will be fed into an array (awesomesauce), and kept there.
Once there, it's then possible to call Yara to scan each part. For example, if an email contains an attachment
plus the body of text, the array would essentially contain 3 parts: the headers, the 
next part could be the body, and the third part would be the binary data of the attachment. 

For the headers + body, this is where the slim Yara ruleset comes into play. When scanned, we're just looking for known
bad IP addresses or links to domains that we know are bad. Scanning with the whole full ruleset adds un-needed overhead. 

For the attachment, the base64 blob is decoded, and saved as an array. It's important to maintain the binary 
data, as this can be used to find evilness from binary / malware-based Yara rules. 

'''

def parse_the_email(my_email):
	msg = email.message_from_string(my_email)
	for part in msg.walk():
		awesome_sauce.append(part.get_payload(decode=True)) # Saves each piece into memory of awesome_sauce array
		if part["to"] != None: my_to.append(part["to"])
		if part["bcc"] != None: my_to.append(part["bcc"])
		if part["cc"] != None: my_to.append(part["cc"])
		if part["from"] != None: my_from.append(part["from"])
		if part["subject"] != None: my_subject.append(part["subject"])
		if part["date"] != None: my_date.append(part["date"])
		if part["content-disposition"] != None: my_attachments.append(clean_attachment_name(part["content-disposition"])) # grab attachment names

	#if awesome_s_check == 1: print awesome_sauce
	for each in awesome_sauce:
		try: # skip for none types


			# BEGIN FINIKY CODE SNIPPET #
			# This section is for base64 that isn't correctly ended / some other hankiness went on
			if each.find(" ") == -1 and len(each) != 0:
				each = each.replace("\r", "").replace("\n", "") # for those finiky base64 blobs 
				#each +="="
				eq_count = each.count("=")
				true_b64 = len(each)%4
			
				if true_b64 != 0:
					each = each.replace("=", "")
					each += (4-(len(each)%4)) * "=" # math to calculate how long the padding *should* be for the base64 blob
				awesome_sauce.append(base64.b64decode(each))
		except:
			pass

	#if awesome_s_check == 1: print base64.b64decode(awesome_sauce[4].replace("\r", "").replace("\n", "") + "=")

	if debug == 1: print "[D] Email Array Length: " + str(len(awesome_sauce))
	temp = my_email.lower() # lowercase email
	if temp.find("attachment") != -1: # Because attachment can be Attachment, attachment, ATTACHMENT, or some other thing to break analysis
		if debug == 1: print "[D] I has attachments"
		rules = yara.compile("yara_include.yar", includes=True) # Full Yara rule set
	else:
		rules = yara.compile("yara_headers.yar", includes=True) # Why scan with "attachment" set if there are no attachments? Again, +50% performance benifit from doing this check. +)
		if debug == 1: print "[D] No attachment"
	

	for each in awesome_sauce: # for each part in the email...
		if each != None:
			matches = rules.match(data=each, callback=mycallback) # if it's not none, check for Yara matches
			tMd5 = hashlib.md5(each).hexdigest()
			tSha256 = hashlib.sha256(each).hexdigest()
			tSsdeep = ssdeep.hash(each)#hashlib.sha256(each).hexdigest() #ssdeep.hash(each)
			# gotta hash 'em all gotta hash 'em all...
			md5_hashes.append(tMd5)
			sha256_hashes.append(tSha256)
			ssdeep_hashes.append(tSsdeep)
			
			my_db.execute("INSERT INTO hash_db VALUES (\'" + my_uuid + "\', \'" + tMd5 + "\', \'" + tSha256 + "\', \'" + tSsdeep + "\')")

			# and pull out / clean all links
			temp = extract_my_links(each)
			for zing in temp:
				my_links.append(zing)
			for blue in matches:
				#print each
				
				yara_hit.append(blue) # makes it cleaner for pushing hits on the back end



awesome_sauce = [] # decoded payloads
my_to = [] # To: field
my_from = [] # From: field
my_subject = [] # Do I really need to keep going...?
my_date = []
my_attachments = []
user_message = [] # Pulled from Yara meta message= field

md5_hashes = []
sha256_hashes = []
ssdeep_hashes = []

my_links = [] # Regex'ed links from email
cleaned_links = []  # parsed / cleaned domains, for SEIM's and other fun stuff
yara_hit = [] # duh

my_email = quopri.decodestring(sys.stdin.read()) # reads email from stdin 

parse_the_email(my_email) # Does the magic, calls def parse_the_email(email)


yara_hit = list(set(yara_hit)) # sort / uniq them all. Better to do this now than on the backend with un-needed duplication
user_message = list(set(user_message)) # Sorts / uniq's user messages. See above comment
md5_hashes = list(set(md5_hashes))

cur_stats = ""
my_to = clean_addresses(my_to)
my_from = clean_addresses(my_from)
my_links = list(set(my_links)) # removes duplication

#print len(yara_hit)
for blue in yara_hit:
	my_db.execute("INSERT INTO yara_hits VALUES (\'" + my_uuid + "\', \'" + str(blue) + "\')")
if debug == 1: 
	for each in my_links:
		cUrl = clean_url(each)
		print "Pivotable: " + "http://www.dshield.org/ipinfo.html?ip=" + cUrl
		print "Pivotable: " + "https://www.robtex.com/dns/" + cUrl + ".html"	
		print "Pivotable: " + "https://www.robtex.com/ip/" + cUrl + ".html"
		print "Pivotable: " + "http://network-tools.com/default.asp?prog=express&host=" + cUrl
		cleaned_links.append(cUrl)
		#print "INSERT INTO urls (\'" + my_uuid + "\', \'" + each + "\', \'" + cUrl + "\')"
		try:
			my_db.execute("INSERT INTO urls VALUES (\'" + my_uuid + "\', \'" + each.replace("<", "").replace(">", "") + "\', \'" + cUrl + "\')")
		except:
			print "ERRORS ON " + my_uuid + cUrl

		
#cleaned_links = list(set(cleaned_links)) # removes duplication

# This prints everything out, to show what the final output would look like. Here would be a good time
# to throw it all into the DB

if debug == 1: print str(user_message).replace("[", "").replace("'", "").replace("]", "") + "\n\nTo: " + str(my_to) + "\nFrom: " + str(my_from) + "\nSubject: " + str(my_subject) + "\nDate: " + str(my_date) + "\nAttachments: " + str(my_attachments) + "\nDetection Signatures: " + str(yara_hit) + "\nReporting Mechanism: " + str(cur_stats) + "\nEmail ID: " +str(my_uuid) + "\nMD5 hashes: " + str(md5_hashes) + "\nSha256 Hashes: " + str(sha256_hashes) + "\nSSDeep: " + str(ssdeep_hashes) + "\nLinks: " + str(my_links).replace(".", "[d]") + "\nCleaned Links: " + str(cleaned_links).replace(".", "[d]")
# CREATE TABLE email_meta(key varchar, date varchar, attachment varchar, reporting_mechanism varchar, email varchar);

my_db.execute("INSERT INTO email_meta VALUES (\'" + my_uuid + "\', \"" + str(my_date) + "\", \"" + str(my_to) + "\", \"" + str(my_from) +  "\", \"" + str(my_subject) + "\", \"" + str(my_attachments) + "\", \'" + str(cur_stats) + "\', \'" + "entireEmailHere" + "\')")
vtResults = virustotalApi(sha256_hashes)
print vtResults

# To save the email
open ("emails/" + my_uuid, "wb").write(my_email)

#cef_my_hash(data, c_from, c_to, c_key, c_subject, c_attachments, c_reporting):

# md5_hashes = []
# sha256_hashes = []
# ssdeep_hashes = []

# Check for similarities
incr = 0
for each in my_to:
	if len(str(my_db.execute('select * from email_meta where e_to like "%' + each + '%" and key != "' + my_uuid + '"').fetchall())) > 2:
		print "THERES AN EMAIL MATCHING RECIPIENT"
		incr +=1

for each in my_from:
	if len(str(my_db.execute('select * from email_meta where e_from like "%' + each + '%" and key != "' + my_uuid + '"').fetchall())) > 2:
		print "THERES AN EMAIL MATCHING SENDER"
		incr +=1

for each in my_subject:
	if len(str(my_db.execute('select * from email_meta where e_subject like "%' + each + '%" and key != "' + my_uuid + '"').fetchall())) > 2:
		print "THERES AN EMAIL MATCHING SUBJECT"
		incr +=1

for each in my_attachments:
	if len(str(my_db.execute('select * from email_meta where attachment like "%' + each + '%" and key != "' + my_uuid + '"').fetchall())) > 2:
		print "THERES AN EMAIL MATCHING ATTACHMENT"
		incr +=1

for each in yara_hit:
	if len(str(my_db.execute('select * from yara_hits where hit like "%' + str(each) + '%" and key != "' + my_uuid + '"').fetchall())) > 2:
		print "THERES AN EMAIL MATCHING YARA HIT"
		incr +=1

for each in cleaned_links:
	if len(str(my_db.execute('select * from urls where cleaned_url like "%' + str(each) + '%" and key != "' + my_uuid + '"').fetchall())) > 2:
		print "THERES A LINK MATCH IN THE HIT"
		incr +=1

if incr >=2:
	print "Clustering! We have a match!"
conn.commit()
conn.close()

# To, From, Subject, Date, Attachments, Detection Signatures, Reporting Mechanism, Email ID, MD5 Hashes, URLs, Clean URLs
# writes out the .csv file. Mostly for debugging here
open (outFile, "a").write("\"" + str(my_to) + "\",\"" + str(my_from) + "\",\"" + str(my_subject) + "\",\"" + str(my_date) + "\",\"" + str(my_attachments) + "\",\"" + str(yara_hit) + "\",\"" + str(cur_stats) + "\",\"" +str(my_uuid) + "\",\"" + str(md5_hashes) + "\",\"" + str(my_links).replace(".", "[d]") + "\",\"" + str(cleaned_links).replace(".", "[d]") + "\",\"" + str(sha256_hashes) + "\",\"" + str(ssdeep_hashes) + "\"\n")



