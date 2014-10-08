#!/usr/bin/env python
import sqlite3,os

#CREATE TABLE email_meta(key varchar, date varchar, e_to varchar, e_from varchar, e_subject varchar, attachment varchar, reporting_mechanism varchar, email varchar);
#CREATE TABLE hash_db(key varchar, md5 varchar, sha256 varchar, ssdeep varchar);
#CREATE TABLE urls(key varchar, url varchar, cleaned_url varchar);
#CREATE TABLE yara_hits(key varchar, hit varchar);

if os.path.isfile("clarityData") == False:
	conn = sqlite3.connect('clarityData')
	c = conn.cursor()
	c.execute("""CREATE TABLE email_meta(key varchar, date varchar, e_to varchar, e_from varchar, e_subject varchar, attachment varchar, reporting_mechanism varchar, email varchar)""")
	c.execute("""CREATE TABLE hash_db(key varchar, md5 varchar, sha256 varchar, ssdeep varchar)""")
	c.execute("""CREATE TABLE urls(key varchar, url varchar, cleaned_url varchar);""")
	c.execute("""CREATE TABLE yara_hits(key varchar, hit varchar)""")
