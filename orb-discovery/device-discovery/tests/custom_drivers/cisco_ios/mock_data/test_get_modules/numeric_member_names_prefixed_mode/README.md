Mock data is hand-authored to exercise bare-numeric member NAME rows, not
captured from a device.

The chassis is a plain Catalyst 9300, so `Te1/1/1` has a removable parent
module the inventory failed to report and must stay declined; the point under
test is member detection, not promotion.
