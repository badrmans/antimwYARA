rule antimw 
{

    meta:
        last_updated = "2022-01-05"
        author = "badrmans"
        description = "a YARA rule to protect against Unknown_Malware.exe"

    strings:
        $string1 = "This benign malware is written for malware analysis purposes. It causes no harm to your computer" wide
        // this rule will simply search for the above string which we've found inside the malware written in ascii 

    condition:
        ($string1 and 1)
        // since we know for sure that the malware will contain this string, no other conditions are needed
}
