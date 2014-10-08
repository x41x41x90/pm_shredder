rule PM_Paypal_Spam
{

strings:
	$a1 = "46.165.252.13"
	$a2 = "@peypal.com" nocase
condition:
	any of them

}

rule PM_Voicemail_Spam
{

strings:
	$a1 = "nepal-himalaya-trekking.de" nocase
	$a2 = ".de/archive/" nocase
	$a3 = "stopp-waldbahn.de" nocase
	$a4 = "icteraangeboden.nl" nocase
	$a5 = ".nl/message/" nocase
	
	$b1 = "Subject: Voice Message" nocase
	$b2 = "Thread-Topic: Voice Message" nocase

condition:
	any of ($a*) or all of ($b*)

}