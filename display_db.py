#!/usr/bin/env python
import sqlite3,sys
conn = sqlite3.connect("clarityData")
c = conn.cursor()

if len(sys.argv) == 1:
	c.execute("select * from yara_hits")
	temp = c.fetchall()
	print "<table><tr><td>"
	print "### Emails with Yara hits ###<br><div style='height:240px;width:480px;border:1px solid #ccc;overflow:scroll;>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]) ,bla) + "<br>"
	print "</div></td><td>"

	c.execute("select * from urls")
	temp = c.fetchall()
	print "<tr><td>"
	print "### Links in Emails ###<br><div style='height:240px;width:480px;border:1px solid #ccc;overflow:scroll;>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(".", "[d]").replace(str(each[0]), bla) + "<br>"
	print "</div></td><td>"

	c.execute("select * from hash_db")
	temp = c.fetchall()
	print "### Hashes ###<br><div style='height:240px;width:480px;border:1px solid #ccc;overflow:scroll;>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]), bla) + "<br>"
	print "</div></td></tr>"

	c.execute ("select * from email_meta")
	temp = c.fetchall()
	print "<tr><td>"
	print "### Email ###<br><div style='height:240px;width:480px;border:1px solid #ccc;overflow:scroll;>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]), bla) +"<br>"
	print "</div></td><td><img src='wolf.jpeg'></td></tr></table>"
else:
	print "### Data pivot ###<br>"
	c.execute("select * from yara_hits where key is '" + str(sys.argv[1]) + "'")
	temp = c.fetchall()
	print "### Yara hits ###<br>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]), bla) +"<br>"
	c.execute("select * from email_meta where key is '" + str(sys.argv[1]) + "'")
	temp = c.fetchall()
	print "### email meta ###<br>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]), bla) +"<br>"
	c.execute("select * from hash_db where key is '" + str(sys.argv[1]) + "'")
	temp = c.fetchall()
	print "### hashes ###<br>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]), bla) +"<br>"
	c.execute("select * from urls where key is '" + str(sys.argv[1]) + "'")
	temp = c.fetchall()
	print "### urls ###<br>"
	for each in temp:
		bla = "<a href='http://127.0.0.1/test.php?q=" + str(each[0]) + "'>" + str(each[0]) + "</a>"		
		print str(each).replace(str(each[0]), bla)+"<br>"
	print "<br>### FULL EMAIL ### <BR><BR>" + a
