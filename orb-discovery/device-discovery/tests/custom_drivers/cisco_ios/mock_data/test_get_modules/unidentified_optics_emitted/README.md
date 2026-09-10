Hand-authored from the inventory reported in issue #556, not captured from a
device. The C9200L's Te1/1/3 and Te1/1/4 are DAC cables: the switch serialises
them but reports no PID, so before #578 they were dropped and the operator got
two optics where four are installed.

Te1/1/1 and Te1/1/2 are identified and must be unaffected, which is what makes
this fixture a regression guard as well as a feature test.
