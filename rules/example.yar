rule Example_PE_MZ
{
  meta:
    description = "Example rule shipped with SigLens"
  strings:
    $mz = { 4D 5A }
  condition:
    uint16(0) == 0x5A4D and $mz at 0
}
