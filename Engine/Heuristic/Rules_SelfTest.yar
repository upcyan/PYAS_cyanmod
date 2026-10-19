// Self-test rules. These exist so a user can verify detection end to end with a
// published, harmless marker instead of hunting for a real sample.
//
// The signature is written as hex on purpose: an ASCII copy of the marker inside
// this file would make the rule match its own source during a full scan.

rule Test_EICAR_StandardAntivirusTestFile
{
    meta:
        description = "EICAR standard antivirus test file: a harmless fixed marker published by EICAR so users can verify detection, blocking and quarantine"
        author = "PYAS Security"
        date = "2026-10-19"
        scope = "self-test and demonstration only; this is not malware and carries no payload"
        evidence = "fixed 68-byte ASCII marker published by the European Institute for Computer Antivirus Research; stored as hex so this rule cannot match its own source"
        attribution = "not a threat family; matched on purpose so protection can be checked without a live sample"
        severity = "test"
    strings:
        // The published 68-byte EICAR marker, byte for byte.
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37
                   43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41
                   4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B
                   48 2A }
    condition:
        filesize < 1MB and $eicar
}
