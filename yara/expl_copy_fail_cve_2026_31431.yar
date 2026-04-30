rule EXPL_LNX_Copy_Fail_Artefacts_CVE_2026_31431_Apr26 {
   meta:
      description = "Detects forensic artifacts related to public Copy Fail (CVE-2026-31431) exploit PoCs, including known tiny ELF shell payloads, Python exploit code fragments, AF_ALG/authencesn/splice usage patterns, public PoC URLs, and other indicators observed in online proof-of-concept material."
      author = "Florian Roth"
      reference = "https://copy.fail"
      reference_1 = "https://github.com/tgies/copy-fail-c"
      reference_2 = "https://github.com/theori-io/copy-fail-CVE-2026-31431"
      reference_3 = "https://hackerspace.pl/~q3k/alpine.py"
      date = "2026-04-30"
      score = 75
   strings:
      // Network indicators (e.g. in bash history, logs, etc.)
      $xs1 = "curl https://copy.fail/exp" ascii

      // Code fragments from public PoCs
      $x1 = "| python3 && su"
      $x2 = "g.open(\"/usr/bin/su\",0);i=0;"
      $x3 = "[-] page-cache mutation failed"
      $x4 = "[+] /etc/passwd page cache mutated"
      $x5 = "bind(AF_ALG: authencesn(hmac(sha256),cbc(aes)))"

      // Tiny x86-64 ELF shell payload: setuid(0) -> execve("/bin/sh") -> exit(0)
      $xc1 = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 40 00 00 00 00 00 00 9e 00 00 00 00 00 00 00 9e 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 31 c0 31 ff b0 69 0f 05 48 8d 3d 0f 00 00 00 31 f6 6a 3b 58 99 0f 05 31 ff 6a 3c 58 0f 05 2f 62 69 6e 2f 73 68 00 00 00 }
      // Tiny AArch64 Linux ELF shell payload: setuid(0) -> execve("/bin/sh") -> exit(0)
      $xc2 = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 b7 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 ac 00 00 00 00 00 00 00 ac 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 80 d2 48 12 80 d2 01 00 00 d4 00 01 00 10 01 00 80 d2 02 00 80 d2 a8 1b 80 d2 01 00 00 d4 00 00 80 d2 a8 0b 80 d2 01 00 00 d4 2f 62 69 6e 2f 73 68 00 }
   condition:
      1 of ($x*)
}
