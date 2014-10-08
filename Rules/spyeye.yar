rule spyeye_tracker {
strings:
	$d0 = "beisentse.net"
	$d1 = "beromder56.com"
	$d2 = "detadomain.su"
	$d3 = "doemguing.net"
	$d4 = "futuretelefonica.com"
	$d5 = "gate.eyeonarte.it"
	$d6 = "helen33nasanorth.com"
	$d7 = "sebortemesd5.com"
	$d8 = "stendtlong.net"
	$d9 = "yawclovm.net"
	$d10 = "188.190.126.173"
	$d11 = "188.190.126.175"
	$d12 = "188.190.126.176"
	$d13 = "193.106.31.12"
	$d14 = "193.107.17.62"
	$d15 = "194.44.157.130"
	$d16 = "46.166.143.56"
	$d17 = "91.213.217.36"
	$d18 = "91.220.62.112"
	$d19 = "91.220.62.190"
	$d20 = "93.171.202.70"
	$d21 = "94.63.149.51"
condition:
	any of them
}