/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-06-25
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule meterpreter_reverse_tcp {
   meta:
      description = "meterpreter reverse tcp session may be open"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-06-25"
      hash1 = "f9b0d98e29556216aebdf568ba7779d5575735ba576b8b82659e54236190b88c"
   strings:
      $s1 = "Error reading private key %s - mbedTLS: (-0x%04X) %s" fullword ascii
      $s2 = "processing command: %u id: '%s'" fullword ascii
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii
      $s4 = "0 0 0 0 PC Service User:" fullword ascii
      $s5 = "Dumping cert info:" fullword ascii
      $s6 = "Error reading client cert file %s - mbedTLS: (-0x%04X) %s" fullword ascii
      $s7 = "[fqdn] gethostbyaddr(%s) failed: %s" fullword ascii
      $s8 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii
      $s9 = "process_new: got %zd byte executable to run in memory" fullword ascii
      $s10 = "[fqdn] gethostbyname(%s) failed: %s" fullword ascii
      $s11 = "thread vulnerable" fullword ascii
      $s12 = /\/(\d+\.)(\d+\.)(\d+\.)(\d+)/
   condition:
      uint16(0) == 0x457f and
      8 of them
}