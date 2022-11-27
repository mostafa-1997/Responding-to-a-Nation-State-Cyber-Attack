rule unknown_threat {
        meta:
                Author = "Moustafa"
                Description = "the rule detects the presence of the callout domain to the command-and-control"
        strings:
                $hfs_m = "http://darkl0rd.com:7758/SSH-T"
		$hfs_s = "http://darkl0rd.com:7758/SSH-One"
        condition:
                all of them

}