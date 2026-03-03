# Vulnerability Disclosure Tracking - found_bugs

> This table tracks all vulnerabilities discovered by STAFF in the found_bugs directory for VulnCheck submission.

_Last updated: 2026-03-03_

| Bug ID | Bug Directory | Brand | Device Category | Product | Tested Version | Module/Component | Status | Recipient |
|---:|---|---|---|---|---|---|---|---|
| 0 | DAP-2310_atp | D-Link | Access Point | DAP-2310 | v1.00_o772 | atp | pending | VulnCheck |
| 1 | DAP-2310_udhcpd | D-Link | Access Point | DAP-2310 | v1.00_o772 | udhcpd | pending | VulnCheck |
| 2 | DAP-2310_xmldb | D-Link | Access Point | DAP-2310 | v1.00_o772 | xmldb | pending | VulnCheck |
| 3 | DAP-2310_xmldb_2 | D-Link | Access Point | DAP-2310 | v1.00_o772 | xmldb | pending | VulnCheck |
| 4 | DGN3500_mini_httpd | NETGEAR | Router | DGN3500 | V1.1.00.30_NA | mini_httpd | pending | VulnCheck |
| 5 | DGN3500_rc | NETGEAR | Router | DGN3500 | V1.1.00.30_NA | rc | pending | VulnCheck |
| 6 | DGN3500_setup.cgi | NETGEAR | Router | DGN3500 | V1.1.00.30_NA | setup.cgi | pending | VulnCheck |
| 7 | DGND3300_mini_httpd | NETGEAR | Router | DGND3300 | V1.1.00.22_NA | mini_httpd | pending | VulnCheck |
| 8 | DGND3300_setup.cgi | NETGEAR | Router | DGND3300 | V1.1.00.22_NA | setup.cgi | pending | VulnCheck |
| 9 | DIR-300_atp | D-Link | Router | DIR-300 | v1.03_7c | atp | pending | VulnCheck |
| 10 | DIR-300_atp_2 | D-Link | Router | DIR-300 | v1.03_7c | atp | pending | VulnCheck |
| 11 | DIR-300_udhcpd | D-Link | Router | DIR-300 | v1.03_7c | udhcpd | pending | VulnCheck |
| 12 | DIR-300_xmldb | D-Link | Router | DIR-300 | v1.03_7c | xmldb | pending | VulnCheck |
| 13 | JNR3210_mini_httpd | NETGEAR | Router | JNR3210 | V1.1.0.14 | mini_httpd | pending | VulnCheck |
| 14 | JNR3210_mini_httpd_2 | NETGEAR | Router | JNR3210 | V1.1.0.14 | mini_httpd | pending | VulnCheck |
| 15 | JNR3210_setup.cgi | NETGEAR | Router | JNR3210 | V1.1.0.14 | setup.cgi | pending | VulnCheck |
| 16 | JNR3210_setup.cgi_2 | NETGEAR | Router | JNR3210 | V1.1.0.14 | setup.cgi | pending | VulnCheck |
| 17 | TL-WPA8630_ledschd | TP-Link | Range Extender | TL-WPA8630 | V2_171011 | ledschd | pending | VulnCheck |
| 18 | TV-IP121WN_view.cgi | TRENDnet | IP Camera | TV-IP121WN | 1.2.2 | view.cgi | pending | VulnCheck |
| 19 | TV-IP651WI_alphapd | TRENDnet | IP Camera | TV-IP651WI | V1_1.07.01 | alphapd | pending | VulnCheck |
| 20 | WRT320N_httpd | Linksys | Router | WRT320N | 1.0.05.002_20110331 | httpd | pending | VulnCheck |


## Summary

- **Total Bugs:** 21
- **Unique Firmware:** 9
- **Vendors:** D-Link, Linksys, NETGEAR, TP-Link, TRENDnet

## Bug Directory Structure

Each bug directory follows the naming convention: `<FIRMWARE>_<MODULE>_[<N>]`

- The directory contains a vulnerability report (.docx) and PoC seeds
- `_2`, `_3`, etc. suffixes indicate multiple distinct bugs in the same firmware/module combination
- All bugs are pending VulnCheck review and CVE assignment

## Notes

- **Status:** All entries are currently "pending" VulnCheck review
- **Module/Component:** Extracted from bug directory name
- **Tested Version:** Matches the firmware version used during testing

---

For reproduction instructions, see [README_VulnCheck.md](README_VulnCheck.md)
