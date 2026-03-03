# VulnCheck Bug Reproduction Guide

This guide provides step-by-step instructions to reproduce all vulnerabilities discovered by STAFF and documented in the `found_bugs` directory.

## Prerequisites

### System Requirements
- Linux-based system (tested on Ubuntu/Debian)
- [Docker](https://docs.docker.com/get-docker/) installed

### Installation & Setup

1. **Clone the STAFF repository**
   ```bash
   git clone https://github.com/alessioizzillo/STAFF.git
   cd STAFF
   ```

2. **Build the Docker image**
   ```bash
   ./docker.sh build
   ```

3. **Run the Docker container with bridge network**
   ```bash
   ./docker.sh run_bridge STAFF 0,1     # Replace 0,1 with CPU cores to assign
   ```

4. **Attach to the container**
   ```bash
   ./docker attach STAFF
   ```

5. **Inside the container, run setup**
   ```bash
   ./install.sh
   make
   ```

6. **Detach from container** (press `Ctrl-A + D`)

7. **Save the container state**
   ```bash
   docker commit STAFF staff
   ```

### Create FirmAE Images

Before reproducing bugs, you must create FirmAE images for the firmware. This step prepares the emulation environment.

1. **Ensure firmware files are in the correct directories** inside the container:
   ```
   firmwares/
   ├── dlink/
   ├── linksys/
   ├── netgear/
   ├── tplink/
   └── trendnet/
   ```

2. **Attach to the container**
   ```bash
   ./docker attach STAFF
   ```

3. **Inside the container, edit `config.ini`** to set mode to `check`:
   ```ini
   [GENERAL]
   mode = check
   firmware = all
   ```

   Or for a specific firmware:
   ```ini
   [GENERAL]
   mode = check
   firmware = dlink/dap2310_v1.00_o772.bin
   ```

4. **Run the image generation**
   ```bash
   python3 start.py --keep_config 1
   ```

   This will create FirmAE images for all firmware (or the specified one) needed for bug reproduction.


**Note:** This step only needs to be done once for each firmware image. After FirmAE images are created, you can proceed with bug reproduction.

---

## Bug Reproduction Commands

Each bug can be reproduced using the `python3 start.py --test` command **inside the Docker container**. Below are the commands grouped by bug.

**Important:** All commands must be executed inside the STAFF Docker container. Attach to it first:
```bash
./docker attach STAFF
```

---

## DAP-2310 (D-Link)

**Firmware:** dlink/dap2310_v1.00_o772.bin  
**Version:** v1.00_o772  
**Type:** Access Point  
**Architecture:** MIPSEB  

### Bug #1: DAP-2310_atp

**Module:** atp  
**Process:** atp,xgi  
**Number of PoCs:** 2  
**Report:** `found_bugs/DAP-2310_atp/DAP-2310_atp.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dap2310_v1.00_o772.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DAP-2310_atp/PoC/redirect_htm__id_1_10_113_1_000004_sig_01_src_000000_op_havoc_rep_4_28921 \
  --process_name atp,xgi
```

```bash
python3 start.py --test \
  --firmware dlink/dap2310_v1.00_o772.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DAP-2310_atp/PoC/rpsubname__id_1_10_45_1_000013_sig_01_src_000000_op_havoc_rep_16_84004 \
  --process_name atp,xgi
```

---

### Bug #2: DAP-2310_udhcpd

**Module:** udhcpd  
**Process:** udhcpd  
**Number of PoCs:** 1  
**Report:** `found_bugs/DAP-2310_udhcpd/DAP-2310_udhcpd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dap2310_v1.00_o772.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DAP-2310_udhcpd/PoC/FUN_00403448__id_0_000004_sig_01_src_000001_op_havoc_rep_4_11889 \
  --process_name udhcpd
```

---

### Bug #3: DAP-2310_xmldb

**Module:** xmldb  
**Process:** xmldb  
**Number of PoCs:** 1  
**Report:** `found_bugs/DAP-2310_xmldb/DAP-2310_xmldb.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dap2310_v1.00_o772.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DAP-2310_xmldb/PoC/FUN_00408618__id_1_5_734_1_000001_sig_01_src_000000_op_havoc_rep_32_7539 \
  --process_name xmldb
```

---

### Bug #4: DAP-2310_xmldb_2

**Module:** xmldb_2  
**Process:** xmldb  
**Number of PoCs:** 1  
**Report:** `found_bugs/DAP-2310_xmldb_2/DAP-2310_xmldb_2.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dap2310_v1.00_o772.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DAP-2310_xmldb_2/PoC/FUN_00408b50__id_1_16_678_3_000012_sig_01_src_000001_op_havoc_rep_4_61712 \
  --process_name xmldb
```

---

## DGN3500 (NETGEAR)

**Firmware:** netgear/DGN3500_V1.1.00.30_NA.zip  
**Version:** V1.1.00.30_NA  
**Type:** Router  
**Architecture:** MIPSEB  

### Bug #5: DGN3500_mini_httpd

**Module:** mini_httpd  
**Process:** mini_httpd  
**Number of PoCs:** 1  
**Report:** `found_bugs/DGN3500_mini_httpd/DGN3500_mini_httpd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_mini_httpd/PoC/FUN_00410e6c__id_000159_orig_id_000079_src_000000_op_ext_UI_pos_26_15882 \
  --process_name mini_httpd
```

---

### Bug #6: DGN3500_rc

**Module:** rc  
**Process:** rc  
**Number of PoCs:** 1  
**Report:** `found_bugs/DGN3500_rc/DGN3500_rc.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_rc/PoC/get_sd_info__id_0_000002_sig_01_src_000001_op_havoc_rep_128_9729 \
  --process_name rc
```

---

### Bug #7: DGN3500_setup.cgi

**Module:** setup.cgi  
**Process:** setup.cgi,upgrade_flash.c  
**Number of PoCs:** 8  
**Report:** `found_bugs/DGN3500_setup.cgi/DGN3500_setup.cgi.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/addkeyword__id_1_34_669_1_000008_sig_01_src_000001_op_havoc_rep_16_66122 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/delete__id_0_000004_sig_01_src_000073_op_havoc_rep_128_20370 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/find_val__id_0_000003_sig_01_src_000012_op_havoc_rep_128_5322 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/html_parser__id_0_000002_sig_01_src_000020_op_havoc_rep_32_9952 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/save__id_1_17_1116_8_000009_sig_01_src_000003_op_havoc_rep_16_60724 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/set_SRouteMetric__id_1_46_1089_13_000002_sig_01_src_000004_op_havoc_rep_32_19130 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/set_TimeZone__id_0_000002_sig_01_src_000000_op_havoc_rep_32_15453 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGN3500_V1.1.00.30_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGN3500_setup.cgi/PoC/set_rule_out__id_0_000006_sig_01_src_000011_op_havoc_rep_32_39019 \
  --process_name setup.cgi,upgrade_flash.c
```

---

## DGND3300 (NETGEAR)

**Firmware:** netgear/DGND3300_V1.1.00.22_NA.zip  
**Version:** V1.1.00.22_NA  
**Type:** Router  
**Architecture:** MIPSEB  

### Bug #8: DGND3300_mini_httpd

**Module:** mini_httpd  
**Process:** mini_httpd  
**Number of PoCs:** 2  
**Report:** `found_bugs/DGND3300_mini_httpd/DGND3300_mini_httpd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_mini_httpd/PoC/FUN_004036e8__id_000364_orig_id_000182_src_000007_op_ext_UI_pos_22_486 \
  --process_name mini_httpd
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_mini_httpd/PoC/FUN_0040427c__id_000001_orig_id_000000_src_000000_op_flip16_pos_4_10608 \
  --process_name mini_httpd
```

---

### Bug #9: DGND3300_setup.cgi

**Module:** setup.cgi  
**Process:** setup.cgi,upgrade_flash.c  
**Number of PoCs:** 11  
**Report:** `found_bugs/DGND3300_setup.cgi/DGND3300_setup.cgi.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/addkeyword__id_1_3_669_1_000008_sig_01_src_000001_op_havoc_rep_4_49868 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/del_list__id_0_000003_sig_01_src_000007_op_havoc_rep_64_5324 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/find_val__id_1_3_1071_2_000012_sig_01_src_000002_op_havoc_rep_2_80845 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/get_WAN_ipType__id_0_000011_sig_01_src_000179_op_havoc_rep_32_64319 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/html_parser__id_1_3_1328_4_000015_sig_01_src_000004_op_havoc_rep_4_61317 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/save__id_0_000005_sig_01_src_000035_op_havoc_rep_64_19555 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/set_SRouteMetric__id_1_13_1121_15_000010_sig_01_src_000004_op_havoc_rep_16_26214 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/set_TimeZone__id_0_000001_sig_01_src_000003_op_havoc_rep_128_1149 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/set_WAN_ipType__id_0_000005_sig_01_src_000001_op_havoc_rep_64_16652 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/set_rule_in__id_0_000006_sig_01_src_000026_op_havoc_rep_8_12766 \
  --process_name setup.cgi,upgrade_flash.c
```

```bash
python3 start.py --test \
  --firmware netgear/DGND3300_V1.1.00.22_NA.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DGND3300_setup.cgi/PoC/set_rule_out__id_0_000001_sig_01_src_000012_op_havoc_rep_64_2723 \
  --process_name setup.cgi,upgrade_flash.c
```

---

## DIR-300 (D-Link)

**Firmware:** dlink/dir300_v1.03_7c.bin  
**Version:** v1.03_7c  
**Type:** Router  
**Architecture:** MIPSEB  

### Bug #10: DIR-300_atp

**Module:** atp  
**Process:** atp,xgi  
**Number of PoCs:** 2  
**Report:** `found_bugs/DIR-300_atp/DIR-300_atp.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dir300_v1.03_7c.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DIR-300_atp/PoC/ExeShell__id_1_10_90_1_000007_sig_01_src_000003_op_havoc_rep_16_30978 \
  --process_name atp,xgi
```

```bash
python3 start.py --test \
  --firmware dlink/dir300_v1.03_7c.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DIR-300_atp/PoC/redirect_htm__id_0_000000_sig_01_src_000387_op_havoc_rep_32_41676 \
  --process_name atp,xgi
```

---

### Bug #11: DIR-300_atp_2

**Module:** atp_2  
**Process:** atp,xgi  
**Number of PoCs:** 1  
**Report:** `found_bugs/DIR-300_atp_2/DIR-300_atp_2.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dir300_v1.03_7c.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DIR-300_atp_2/PoC/do_xgi__id_1_10_90_1_000003_sig_01_src_000003_op_havoc_rep_4_7063 \
  --process_name atp,xgi
```

---

### Bug #12: DIR-300_udhcpd

**Module:** udhcpd  
**Process:** udhcpd  
**Number of PoCs:** 1  
**Report:** `found_bugs/DIR-300_udhcpd/DIR-300_udhcpd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dir300_v1.03_7c.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DIR-300_udhcpd/PoC/FUN_00402f70__id_1_32_604_1_000006_sig_01_src_000001_op_havoc_rep_16_28456 \
  --process_name udhcpd
```

---

### Bug #13: DIR-300_xmldb

**Module:** xmldb  
**Process:** xmldb  
**Number of PoCs:** 1  
**Report:** `found_bugs/DIR-300_xmldb/DIR-300_xmldb.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware dlink/dir300_v1.03_7c.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/DIR-300_xmldb/PoC/FUN_0040b7e4__id_1_58_651_1_000006_sig_01_src_000001_op_havoc_rep_2_60674 \
  --process_name xmldb
```

---

## JNR3210 (NETGEAR)

**Firmware:** netgear/JNR3210_Firmware_Version_1.1.0.14.zip  
**Version:** V1.1.0.14  
**Type:** Router  
**Architecture:** MIPSEB  

### Bug #14: JNR3210_mini_httpd

**Module:** mini_httpd  
**Process:** mini_httpd  
**Number of PoCs:** 1  
**Report:** `found_bugs/JNR3210_mini_httpd/JNR3210_mini_httpd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/JNR3210_Firmware_Version_1.1.0.14.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/JNR3210_mini_httpd/PoC/FUN_00403acc__id_1_11_13_4_000003_sig_01_src_000001_op_havoc_rep_4_32330 \
  --process_name mini_httpd
```

---

### Bug #15: JNR3210_mini_httpd_2

**Module:** mini_httpd_2  
**Process:** mini_httpd  
**Number of PoCs:** 1  
**Report:** `found_bugs/JNR3210_mini_httpd_2/JNR3210_mini_httpd_2.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/JNR3210_Firmware_Version_1.1.0.14.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/JNR3210_mini_httpd_2/PoC/FUN_00405c88__id_000023_orig_id_000010_src_000000_op_ext_UI_pos_77_3850 \
  --process_name mini_httpd
```

---

### Bug #16: JNR3210_setup.cgi

**Module:** setup.cgi  
**Process:** setup.cgi 
**Number of PoCs:** 1  
**Report:** `found_bugs/JNR3210_setup.cgi/JNR3210_setup.cgi.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/JNR3210_Firmware_Version_1.1.0.14.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/JNR3210_setup.cgi/PoC/html_parser__id_000001_orig_id_000000_sig_01_src_000000_op_ext_UI_pos_19_2730 \
  --process_name setup.cgi
```

---

### Bug #17: JNR3210_setup.cgi_2

**Module:** setup.cgi_2  
**Process:** setup.cgi,upgrade_flash.c  
**Number of PoCs:** 1  
**Report:** `found_bugs/JNR3210_setup.cgi_2/JNR3210_setup.cgi_2.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware netgear/JNR3210_Firmware_Version_1.1.0.14.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/JNR3210_setup.cgi_2/PoC/upgrade_main__id_1_43_89_1_000000_sig_01_src_000003_op_havoc_rep_4_9407 \
  --process_name setup.cgi,upgrade_flash.c
```

---

## TL-WPA8630 (TP-Link)

**Firmware:** tplink/TL-WPA8630_V2_171011.zip  
**Version:** V2_171011  
**Type:** Range Extender  
**Architecture:** MIPSEB  

### Bug #18: TL-WPA8630_ledschd

**Module:** ledschd  
**Process:** ledschd  
**Number of PoCs:** 1  
**Report:** `found_bugs/TL-WPA8630_ledschd/TL-WPA8630_ledschd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware tplink/TL-WPA8630_V2_171011.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/TL-WPA8630_ledschd/PoC/FUN_00402320__id_0_000000_sig_01_src_000032_op_havoc_rep_8_15471 \
  --process_name ledschd
```

---

## TV-IP121WN (TRENDnet)

**Firmware:** trendnet/TV-IP121WN_V1.2.2.66.zip  
**Version:** 1.2.2  
**Type:** IP Camera  
**Architecture:** MIPSEB  

### Bug #19: TV-IP121WN_view.cgi

**Module:** view.cgi  
**Process:** view.cgi  
**Number of PoCs:** 1  
**Report:** `found_bugs/TV-IP121WN_view.cgi/TV-IP121WN_view.cgi.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware trendnet/TV-IP121WN_V1.2.2.66.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/TV-IP121WN_view.cgi/PoC/main__id_0_000000_sig_01_src_000217_op_havoc_rep_128_53969 \
  --process_name view.cgi
```

---

## TV-IP651WI (TRENDnet)

**Firmware:** trendnet/TV-IP651WI_V1_1.07.01.zip  
**Version:** V1_1.07.01  
**Type:** IP Camera  
**Architecture:** MIPSEL  

### Bug #20: TV-IP651WI_alphapd

**Module:** alphapd  
**Process:** alphapd  
**Number of PoCs:** 1  
**Report:** `found_bugs/TV-IP651WI_alphapd/TV-IP651WI_alphapd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware trendnet/TV-IP651WI_V1_1.07.01.zip \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/TV-IP651WI_alphapd/PoC/websCgibinProcessor__id_0_000000_sig_01_src_000144_op_havoc_rep_128_3428 \
  --process_name alphapd
```

---

## WRT320N (Linksys)

**Firmware:** linksys/FW_WRT320N_1.0.05.002_20110331.bin  
**Version:** 1.0.05.002_20110331  
**Type:** Router  
**Architecture:** MIPSEL  

### Bug #21: WRT320N_httpd

**Module:** httpd  
**Process:** httpd  
**Number of PoCs:** 5  
**Report:** `found_bugs/WRT320N_httpd/WRT320N_httpd.docx`  

**Reproduction commands:**

```bash
python3 start.py --test \
  --firmware linksys/FW_WRT320N_1.0.05.002_20110331.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/WRT320N_httpd/PoC/get_cgi__id_000020_orig_id_000006_src_000005_op_ext_UI_pos_1186_58154 \
  --process_name httpd
```

```bash
python3 start.py --test \
  --firmware linksys/FW_WRT320N_1.0.05.002_20110331.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/WRT320N_httpd/PoC/valid_hwaddr__id_0_000001_sig_01_src_000000_op_havoc_rep_32_1038 \
  --process_name httpd
```

```bash
python3 start.py --test \
  --firmware linksys/FW_WRT320N_1.0.05.002_20110331.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/WRT320N_httpd/PoC/validate_cgi__id_000005_orig_id_000001_src_000005_op_ext_UI_pos_1159_57588 \
  --process_name httpd
```

```bash
python3 start.py --test \
  --firmware linksys/FW_WRT320N_1.0.05.002_20110331.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/WRT320N_httpd/PoC/validate_forward_single__id_0_000002_sig_01_src_000001_op_havoc_rep_16_8468 \
  --process_name httpd
```

```bash
python3 start.py --test \
  --firmware linksys/FW_WRT320N_1.0.05.002_20110331.bin \
  --port 80 \
  --timeout 150 \
  --seed_input found_bugs/WRT320N_httpd/PoC/validate_merge_ipaddrs__id_000024_orig_id_000008_src_000005_op_ext_UI_pos_1329_59583 \
  --process_name httpd
```

---

## Notes

1. **Docker Workflow**:
   - All reproduction commands must be executed **inside the Docker container**
   - Use `./docker attach STAFF` to access the container shell
   - The container runs with **bridge network mode** for proper isolation
   - Detach safely with `Ctrl-A + D` to keep processes running

2. **Timeout**: The `--timeout 150` parameter gives the emulator sufficient time to boot and process requests. Adjust if needed.

3. **Port**: All tests use port 80 (HTTP). Bridge network mode handles port isolation automatically.

4. **Expected Behavior**: Each PoC should trigger a crash in the target process. Check the STAFF output for crash indicators ("SIGSEGV").

5. **Crash Logs**: After reproducing a bug, the kernel log containing SEGV information can be found at:
   ```
   FirmAE/scratch/run/<n>/qemu.final.serial.log
   ```
   Where `<n>` is the firmware image ID, which can be looked up in `FirmAE/firm_db_run.csv` by searching for your firmware name.


## Troubleshooting

- **Container not running**: Ensure the Docker container is running with `docker ps`. If not, restart with `./docker.sh run_bridge STAFF 0,1`
- **Cannot attach to container**: Make sure you've created and started the container first
- **Firmware not found**: Ensure firmware files are in the correct directory structure inside the container at `/root/STAFF/firmwares/`
- **Network issues**: The bridge network mode should handle networking automatically. If issues persist, check Docker network configuration
- **Memory errors during testing**: If the container runs out of memory, you can increase the memory limit in `docker.sh` script
- **Port conflicts**: Bridge network mode isolates the container, so port 80 conflicts are unlikely

### Docker-Specific Commands

- **Attach to running container**: `./docker attach STAFF`
- **Detach from container**: Press `Ctrl-A + D` (do not use `Ctrl-C` as it will stop processes)
- **Stop container**: `docker stop STAFF`
- **Remove container**: `docker rm -f STAFF`
- **List running containers**: `docker ps`
- **View container logs**: `docker logs STAFF`

## Documentation

Each bug directory contains:
- `<bug_name>.docx`: Detailed vulnerability report
- `PoC/`: Directory with proof-of-concept exploit seeds

For detailed vulnerability information, refer to the individual .docx reports in each bug directory.

---

*Generated for VulnCheck vulnerability reproduction*
