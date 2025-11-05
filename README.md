
# STAFF
_Stateful Taint‑Assisted Full‑system Firmware Fuzzer_

## Paper

This work has been submitted for review to the **Computers & Security journal** (Elsevier) and is available as a preprint on arXiv:

**STAFF: Stateful Taint-Assisted Full-system Firmware Fuzzing**
Alessio Izzillo, Riccardo Lazzeretti, Emilio Coppa
arXiv preprint cs.CR, 2025
DOI: [10.48550/arXiv.2509.18039](https://doi.org/10.48550/arXiv.2509.18039)
URL: https://arxiv.org/abs/2509.18039

### BibTeX

If you use STAFF in your research, please cite:

```bibtex
@article{izzillo2025staff,
    title={STAFF: Stateful Taint-Assisted Full-system Firmware Fuzzing},
    author={Izzillo, Alessio and Lazzeretti, Riccardo and Coppa, Emilio},
    journal={arXiv preprint cs.CR},
    year={2025},
    doi={10.48550/arXiv.2509.18039}
}
```

# Table of Contents

- [Paper](#paper)

- [Introduction & Motivation](#introduction--motivation)
  - [Motivating Example: Multi-Request, Inter-Binary Vulnerabilities](#motivating-example-multi-request-inter-binary-vulnerabilities)
  - [Key Contributions](#key-contributions)

- [Overview](#overview)
  - [Phase 1: User-driven Multi-Request Recording](#phase-1-user-driven-multi-request-recording)
  - [Phase 2: Intra- and Inter-Service Dependency Analysis](#phase-2-intra--and-inter-service-dependency-analysis)
  - [Phase 3: Protocol-Aware Taint-Guided Fuzzing](#phase-3-protocol-aware-taint-guided-fuzzing)

- [Experimental Assessment](#experimental-assessment)  
  - [Methods Comparison](#methods-comparison)  
  - [Experimental Parameters](#experimental-parameters)  
  - [Dataset](#dataset)

- [Getting Started](#getting-started)  
  - [Prerequisites](#prerequisites)  
  - [Setup & Build](#setup--build)  
  - [Create FirmAE Images](#create-firmae-images)  
  - [Capture a New Interaction](#capture-a-new-interaction)  
  - [Perform a Pre-analysis](#perform-a-pre-analysis)  
  - [Start an Experiment](#start-an-experiment)  
  - [Start a Bunch of Experiments](#start-a-bunch-of-experiments)

## Introduction & Motivation

**STAFF** (_Stateful Taint-Assisted Full-system Firmware Fuzzer_) is an automated fuzzing framework designed to discover bugs in Linux-based firmware software. It addresses the challenge of finding deep-state, inter-service vulnerabilities in embedded systems that expose protocol-based services.

### Motivating Example: Multi-Request, Inter-Binary Vulnerabilities

Modern firmware devices often run multiple cooperating processes that communicate through IPC channels, shared files, and configuration databases. Vulnerabilities in such systems frequently require:
- **Multiple coordinated requests** across different protocol endpoints
- **Cross-process data flows** where input to one service affects execution in another
- **Persistent state** maintained through filesystems or configuration daemons

As an example, STAFF discovered a stack buffer overflow in the D-Link DAP-2310 (v1.00_o772) firmware that requires three distinct HTTP requests affecting three separate processes:

1. **Authentication**: A login request establishes a session
2. **State poisoning**: A DHCP configuration request with oversized parameters gets persisted by the `xmldb` daemon
3. **Trigger**: A configuration commit request causes `xmldb` to unsafely copy the previously stored data, overflowing a 1024-byte stack buffer

![Multi-Request Stack Buffer Overflow Example](img/case-study-new.drawio.svg)

This type of vulnerability cannot be found by:
- Single-process fuzzers (miss inter-service dependencies)
- Stateless fuzzers (miss multi-request sequences)
- Coverage-only guidance (miss subtle data flow dependencies)

### Key Contributions

**STAFF** addresses these challenges through:

1. **Three-Stage Automated Fuzzing Framework**: An integrated pipeline combining user-assisted multi-request recording, whole-system dependency analysis via taint tracking, and dependency-aware protocol fuzzing—automating the entire workflow from seed generation to bug discovery.

2. **Practical Optimizations for Whole-System Analysis**: Novel techniques including byte-annotation heuristics for efficient taint tracking, process-aware coverage tracking to reduce bitmap collisions, and request-sequence minimization to preserve essential dependencies while reducing overhead.

3. **Implementation and Tool Release**: A complete implementation extending DECAF++ for whole-system taint analysis in firmware contexts, with optimizations addressing the performance challenges of system-mode emulation.

4. **Comprehensive Evaluation**: Testing on 15 real-world firmware images (routers, range extenders, IP cameras), discovering 42 bugs with 69% involving inter-binary data flows—demonstrating significant improvements over state-of-the-art tools like TriforceAFL and AFLNet.


## Overview

STAFF operates through three conceptual phases that automate the complete workflow from seed generation to bug discovery:

![STAFF Three-Phase Fuzzing Framework Overview](img/staff_overall.drawio.svg)

### Phase 1: User-driven Multi-Request Recording

The first phase involves capturing representative firmware interactions through manual exploration. Unlike earlier approaches that focus solely on individual services, STAFF is designed to test **all programs** affected by network interactions.

![Phase 1: User-Driven Multi-Request Recording](img/exploration_phase.drawio.svg)

**How it works:**
1. STAFF emulates the firmware image, extracting and mounting the root filesystem with virtualized CPU, memory, peripherals, and network interfaces
2. A user analyst interacts with the emulated firmware (e.g., via web browser) through the virtual network interface
3. STAFF captures all HTTP interactions as network packet traces (PCAPs)
4. Preliminary filtering excludes static content (JavaScript, images, stylesheets)
5. The captured sessions form the initial **seed corpus** for subsequent analysis

**Example:** For the D-Link DAP-2310 firmware, an analyst logs in via `/login.php`, navigates configuration pages (`/index.php`, `/home_sys.php`, `/adv_dhcpd.php`), modifies DHCP settings via POST requests, and commits changes through firmware-specific endpoints (`/cfg_valid.xgi`). All exchanges are captured with protocol order, authentication flow, and session state intact.

### Phase 2: Intra- and Inter-Service Dependency Analysis

The second phase performs fine-grained runtime analysis to understand how input bytes influence firmware execution across multiple processes.

![Phase 2: Intra- and Inter-Service Dependency Analysis](img/pre_analysis_phase.drawio.svg)

**Key Components:**

#### Session-Aware HTTP Request Modeling

STAFF parses captured interactions into structured regions (distinct HTTP requests) using protocol-aware rules:
- Content-Length-based parsing with byte precision
- Chunked transfer encoding reconstruction
- Connection-close semantics for responses without explicit length
- Logical end-tags (e.g., `</html>`) as completeness indicators

This approach is more robust than timeout-based strategies (used by AFLNet), correctly handling partial, malformed, or delayed responses.

#### Whole-System Taint Analysis

STAFF replays requests under emulation with dynamic taint analysis enabled, tracking how input bytes propagate through:
- **Memory accesses**: Load/store operations with program counter, physical address, and byte value
- **IPC channels**: Taint naturally flows through kernel memory regions used for inter-process communication
- **Filesystem operations**: Writer-reader relationships established when one region writes a file that another region later reads

**Example:** In a three-request sequence:
- R₀ (login): Stores `LOGIN` bytes in memory and creates `/var/proc/web/session:1/user/ac_auth`
- R₁ (DHCP config): Loads session file (depends on R₀), stores tainted `192.168.` bytes
- R₂ (commit): Reads session file (depends on R₀), loads `192.168.` bytes from R₁

#### Byte Annotation Heuristic

STAFF uses a scalable single-taint-source approach combined with value-matching (inspired by REDQUEEN) to annotate each input byte with:
- **deps**: Set of region IDs that access this byte
- **PCs**: Set of program counters (basic blocks) that access it

This approach avoids the exponential cost of tracking individual bytes as separate taint sources while still achieving fine-grained precision.

**Output:** Seeds enriched with **taint hints**—actionable metadata about which bytes influence which execution paths and processes.

### Phase 3: Protocol-Aware Taint-Guided Fuzzing

The third phase delivers mutated request sequences to firmware while monitoring for crashes and collecting coverage feedback.

![Phase 3: Protocol-Aware Taint-Guided Fuzzing](img/fuzzing_phase.drawio.svg)

**Key Features:**

1. **Taint-Guided Mutations**: Prioritize mutations of bytes identified as influential during dependency analysis
2. **Protocol Structure Preservation**: Maintain HTTP syntax and semantic correctness
3. **Sequence Minimization**: Replay only essential prefix/suffix regions that affect the mutated region
4. **Multi-Stage Forkservers**: Checkpoint VM state after prefix execution, then fork for each mutation variant—avoiding redundant prefix re-execution

**Coverage Tracking:** Process-aware bitmap tracking that combines program counter with process identifier (inode) to reduce collisions in multi-process execution.

**Result:** Discovery of deep-state bugs requiring coordinated multi-request sequences and cross-process data flows that would be missed by traditional fuzzers.


## Available Modes & Configuration

STAFF's `start.py` script supports multiple operation modes controlled via the `config.ini` file. Below are the available modes and their default configuration parameters.

### Operation Modes

- **run**: Standard firmware emulation without capture
- **run_capture**: Emulate firmware and capture network interactions to PCAP files
- **replay**: Replay previously captured PCAP interactions
- **check**: Verify firmware can be emulated and create FirmAE images
- **pre_analysis**: Perform taint-assisted dependency analysis on captured interactions
- **pre_exp**: Prepare pre-analysis experiments with taint metrics
- **crash_analysis**: Analyze crash outputs and generate reports
- **aflnet_base**: Run AFLNet fuzzer in base mode (stateless)
- **aflnet_state_aware**: Run AFLNet fuzzer with state-aware protocol modeling
- **triforce**: Run TriforceAFL system-mode fuzzer
- **staff_base**: Run STAFF fuzzer in base mode (with taint hints, stateless)
- **staff_state_aware**: Run STAFF fuzzer with state-aware protocol modeling and taint hints

### Default Configuration Parameters

The `config.ini` file organizes parameters into sections:

#### [GENERAL]
- **mode**: Operation mode (default: `run`)
- **firmware**: Firmware path (default: `dlink/dap2310_v1.00_o772.bin`)

#### [CAPTURE]
- **whitelist_keywords**: Include only requests matching these patterns (default: `POST/PUT/.php/.cgi/.xml`)
- **blacklist_keywords**: Exclude requests matching these patterns (default: `.gif/.jpg/.png/.css/.js/.ico/.htm/.html`)

#### [PRE-ANALYSIS]
- **pre_analysis_id**: Pre-analysis experiment identifier (default: `0`)
- **subregion_divisor**: Maximum divisor for subsequence subdivision (default: `10`)
- **min_subregion_len**: Minimum length for subsequences (default: `3`)
- **delta_threshold**: Tolerance for approximate matching (default: `0.15`)

#### [EMULATION_TRACING]
- **include_libraries**: Include library code in coverage tracking (default: `1`)

#### [GENERAL_FUZZING]
- **map_size_pow2**: AFL bitmap size as power of 2 (default: `25` = 32MB)
- **fuzz_tmout**: Total fuzzing timeout in seconds (default: `86400` = 24 hours)
- **timeout**: Per-input execution timeout in milliseconds (default: `120`)
- **afl_no_arith**: Disable arithmetic mutations (default: `1`)
- **afl_no_bitflip**: Disable bitflip mutations (default: `0`)
- **afl_no_interest**: Disable interest heuristic (default: `1`)
- **afl_no_user_extras**: Disable user-supplied extras (default: `1`)
- **afl_no_extras**: Disable all extra tokens (default: `1`)
- **afl_calibration**: Enable calibration stage (default: `1`)
- **afl_shuffle_queue**: Randomize queue order (default: `1`)

#### [AFLNET_FUZZING]
- **region_delimiter**: Delimiter between protocol regions (default: `\x1A\x1A\x1A\x1A`)
- **proto**: Protocol name (default: `http`)
- **region_level_mutation**: Enable region-level mutations (default: `1`)

#### [STAFF_FUZZING]
- **taint_hints_all_at_once**: Apply all taint hints simultaneously (default: `0`)
- **sequence_minimization**: Enable sequence minimization (default: `1`)
- **taint_metrics**: Priority metrics for mutation (default: `rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes`)
- **checkpoint_strategy**: Enable VM snapshot checkpointing (default: `1`)

#### [EXTRA_FUZZING]
- **coverage_tracing**: Coverage tracking mode (default: `taint_block`)
- **stage_max**: Maximum mutations per stage (default: `1`)

### Command-Line Options

`start.py` accepts the following arguments:

```bash
python3 start.py [OPTIONS]

Options:
  --keep_config INT        Keep existing config.ini (default: 1)
  --reset_firmware_images INT  Reset firmware images (default: 0)
  --replay_exp INT         Replay an experiment (default: 0)
  --output STR             Output directory path
  --container_name STR     Container name for the experiment
  --crash_dir STR          Directory containing crash outputs for crash_analysis mode
```

### Output Directories

STAFF organizes outputs in the following directories:

- **extracted_crash_out/**: Extracted and deduplicated crash reports
- **FirmAE/scratch/<mode>/<iid>/outputs/**: Per-experiment fuzzing outputs
  - `crashes/`: Raw crash inputs
  - `crash_traces/`: Stack traces and taint information
  - `fuzzer_stats`: Fuzzing statistics
  - `plot_data`: Time-series coverage and crash data
  - `config.ini`: Experiment configuration
- **pre_analysis_db/**: Taint analysis results from pre-analysis phase
- **experiments_done/**: Completed experiment metadata
- **analysis/**: Analysis scripts and crash databases


## Experimental Assessment

### Methods comparison
In this experimental assessment **STAFF** will be compared with the main state-of-the-art fuzzing methods which could be applied into a stateful full-system context:

- **AFLNet "base"**. It behaves similarly to classic greybox fuzzers like AFL, but adapted for network protocols. It mutates sequences of protocol messages extracted from packet captures (PCAPs), blindly exploring the input space without awareness of the protocol’s state transitions or server responses.

- **AFLNet "state-aware"**. It enhances fuzzing effectiveness by learning a protocol state machine on the fly. It uses server responses to build an intermediate protocol state model (IPSM), identifies target states (especially rarely fuzzed ones), and prioritizes mutations that exercise unexplored transitions or improve coverage.

- **DECAF++ TriforceAFL (from FirmAFL)**. It is a system-mode fork of AFL designed for full-system fuzzing. Unlike classical QEMU user-mode fuzzers, it runs a parallel full-system QEMU VM and injects test cases into the guest via a syscall buffer. This enables extensive fuzzing of firmware in a multi-process environment. However, it does not track state changes or support multi-step testcases, making it less suited for deeply stateful protocol interactions.

- **STAFF "base"**. It enforces into an hybrid-way the method of **AFLNet "base"** strengthening with *taint hints* obtained from the *pre-analysis phase*. 

- **STAFF "state-aware"**. It enforces into an hybrid-way the method of **AFLNet "state-aware"** strengthening with *taint hints* obtained from the *pre-analysis phase*. 

### Experimental parameters

The parameters used into this experimental evaluation are divided in several categories which are described below.

#### PRE-ANALYSIS parameters

**subregion_divisor**
   - *Definition:* A parameter that dynamically limits the maximum size of candidate subregions (subsequences) to be matched against known inputs. It ensures that the subregion length is less than a fraction (typically 1/subregion_divisor) of the total region size.

   - *Purpose:* To avoid overfitting or matching overly large regions that are unlikely to provide meaningful or unique insights.

   - *Example:* If the region is 20 bytes long and subregion_divisor = 2, then only subregions of size <10 will be considered for matching (unless overridden by min_subregion_len).

**min_subregion_len**
   - *Definition:* The minimum allowable length for a subregion to be considered a valid match during taint propagation analysis.

   - *Purpose:* To filter out small, non-informative matches that may occur frequently by chance (e.g., common ASCII characters or short patterns), reducing false positives.

   - *Example:* If min_subregion_len = 4, then subsequences shorter than 4 bytes are ignored even if they match known input bytes.

**delta_threshold**
   - *Definition:* A (typically optional) parameter representing a numerical limit used to quantify acceptable differences between matched regions—for example, in content, length, or offset.

   - *Purpose:* To allow some tolerance when comparing regions, especially in heuristic or approximate matching scenarios (e.g., when detecting slightly modified or shifted data).

   - *Example:* If delta_threshold = 2, then two subsequences may be considered equivalent even if they differ by up to 2 bytes or are shifted by 2 positions.


#### EMULATION_TRACING parameters

**include_libraries**. When enabled, the coverage/tracing bitmap collects PCs from all translation blocks—including those in dynamically‑linked or emulated libraries—rather than restricting to PCs in the main firmware binaries alone.

#### GENERAL_FUZZING parameters

**fuzz_tmout**. A global watchdog timeout for the whole fuzzing run (often in seconds or minutes). When the entire campaign exceeds this, it cleanly shuts down.

**timeout**. The per‑input (or region) execution timeout (in milliseconds) that the fuzzer applies when running your target under QEMU. Inputs taking longer are killed and counted as “hangs.”

**afl_no_arith**. Disable AFL’s built‑in integer‑arithmetic mutations. No “add/subtract constant” operations will be applied.

**afl_no_bitflip**.	Disable AFL’s single‑bit and multi‑bit flip mutations.

**afl_no_interest**. Turn off AFL’s “interest” heuristic: normally AFL skips mutations on bytes it deems uninteresting; with this flag, every byte is equally likely to be mutated.

**afl_no_user_extras**. Disable any user‑supplied extra testcases (via ‑‑extras_dir) from being injected into the mutation queue.

**afl_no_extras**. Disable all extra (dictionary‑ or user‑provided) tokens—only blind mutations and seeds will be used.

**afl_calibration**. Enable AFL’s calibration stage on each new seed: test it multiple times to measure stability (counts of hangs/crashes) before adding it to the queue.

**afl_shuffle_queue**. Randomize the order in which AFL pulls seeds from its queue for mutation, rather than strictly FIFO. This can help avoid starvation of late‑discovered seeds.

#### AFLNET_FUZZING parameters

**region_delimiter**. A special marker byte or sequence that AFLNet treats as the boundary between protocol “regions” (e.g. between messages).

**proto**. The name of the protocol under test (e.g. FTP, RTSP); used to pick the correct parser and state‑machine learner. At the moment, only HTTP is supported.

**region_level_mutation**. Enables higher‑level, message‑or “region”‑granular mutations (only for non-STAFF mutations). When turned on, AFLNet may apply any of these four operators:
   - Replace the current region with a random region drawn from another seed.
   - Insert a random region from another seed at the beginning of the current region.
   - Insert a random region from another seed at the end of the current region.
   - Duplicate the current region, appending a copy immediately after it.

#### STAFF_FUZZING parameters

**sequence_minimization**. Selected an interesting message sequence, this toggles whether to run a reducer that tries to drop extraneous regions while preserving the new coverage or state‑transition. *(See [Overview](#Overview))*

**taint_metric**. A per‑byte score from pre‑analyzed interactions that combines its influence on code flow, process scope, cross‑region dependencies, and persistence. These scores drive a priority queue of (region, offset, length) mutation targets. *(See [Overview](#Overview))*

**checkpoint_strategy**. Specifies that STAFF first executes the unmodified prefix up to the mutation point a single time, takes a VM snapshot via a secondary forkserver, then for each variant forks from that snapshot, applies the mutated region and reattaches the original suffix—thereby avoiding repeated execution of the unchanged prefix. *(See [Overview](#Overview))*

#### EXTRA_FUZZING parameters

**coverage_tracing**. Selects the coverage feedback mode: classic edge‑ or block‑coverage, or taint‑focused variants that report only edges or blocks involving taint‑related loads/stores.

**stage_max**. The maximum number of sequential mutations of the same type to apply to each seed in one go. For example, if *stage_max = 32*, the fuzzer may apply and run up to 32 bit‑flips (or 32 consecutive arithmetic ops, etc.).

### Dataset

The dataset is a curated subset of firmware images originally sourced from the larger [FirmAE](https://github.com/pr0v3rbs/FirmAE) project. It includes firmware for various brands of routers and IP cameras. The selection was performed by analyzing a wide range of images and filtering in only those firmwares that met the following criteria:

- The embedded web server is reachable and explorable.
- The firmware emulates correctly, without critical sections being broken or failing to initialize.
- The interface supports fast and responsive user interactions.
- A valid and simple web session can be captured and replayed using a PCAP trace.
- The web server does not selectively respond only to specific browser clients or reject automated/non-standard user agents.
- The firmware does not require an encrypted or obfuscated login session procedure that prevents reproducible interaction or taint tracing.
- Web authentication must result in actual, replayable HTTP requests (e.g., not just browser pop-ups that don’t produce usable credentialed traffic).
- Firmware was excluded if the embedded web server only presents an informational landing page with static content or external links (e.g., to the vendor's website), without exposing the actual device management interface.

The corresponding firmware images are located in the `firmwares` directory, and the per-firmware user interaction traces can be found in the `pcap` directory. Below is a table summarizing the dataset.

<table style="border-collapse: collapse; width: 100%; color: inherit; border-color: inherit;">
  <tr>
    <td colspan="27" style="border-bottom: 1px solid currentColor;"></td>
  </tr>
  <tr>
    <th style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Brand</th>
    <th style="border-right: 1px solid currentColor;">Firmware Name</th>
    <th style="border-right: 1px solid currentColor;">Device Type</th>
    <th style="border-right: 1px solid currentColor;">Number of PCAPs</th>    
  </tr>
  <!-- Data Row 1 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">ASUS</td>
    <td style="border-right: 1px solid currentColor;">FW_RT_N10U_B1_30043763754.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 2 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">ASUS</td>
    <td style="border-right: 1px solid currentColor;">FW_RT_N53_30043763754.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 3 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">D-Link</td>
    <td style="border-right: 1px solid currentColor;">dap2310_v1.00_o772.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 4 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">D-Link</td>
    <td style="border-right: 1px solid currentColor;">dir300_v1.03_7c.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 5 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">D-Link</td>
    <td style="border-right: 1px solid currentColor;">DIR815A1_FW104b03.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">5</td>
  </tr>
  <!-- Data Row 6 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Linksys</td>
    <td style="border-right: 1px solid currentColor;">FW_RE1000_1.0.02.001_US_20120214_SHIPPING.bin</td>
    <td style="border-right: 1px solid currentColor;">Range Extender</td>
    <td style="border-right: 1px solid currentColor;">2</td>
  </tr>
  <!-- Data Row 7 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Linksys</td>
    <td style="border-right: 1px solid currentColor;">FW_WRT320N_1.0.05.002_20110331.bin</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 8 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Netgear</td>
    <td style="border-right: 1px solid currentColor;">DGN3500-V1.1.00.30_NA.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">5</td>
  </tr>
  <!-- Data Row 9 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Netgear</td>
    <td style="border-right: 1px solid currentColor;">DGND3300_Firmware_Version_1.1.00.22__North_America_.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">5</td>
  </tr>
  <!-- Data Row 10 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">Netgear</td>
    <td style="border-right: 1px solid currentColor;">JNR3210_Firmware_Version_1.1.0.14.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 11 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TP-Link</td>
    <td style="border-right: 1px solid currentColor;">Archer_C2_US__v1_160128.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 12 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TP-Link</td>
    <td style="border-right: 1px solid currentColor;">TL-WPA8630_US__V2_171011.zip</td>
    <td style="border-right: 1px solid currentColor;">Range Extender</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 13 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TRENDnet</td>
    <td style="border-right: 1px solid currentColor;">FW_TV-IP121WN_1.2.2.zip</td>
    <td style="border-right: 1px solid currentColor;">IP Camera</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 14 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TRENDnet</td>
    <td style="border-right: 1px solid currentColor;">FW_TV-IP651WI_V1_1.07.01.zip</td>
    <td style="border-right: 1px solid currentColor;">IP Camera</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <!-- Data Row 15 -->
  <tr>
    <td style="border-left: 1px solid currentColor; border-right: 1px solid currentColor;">TRENDnet</td>
    <td style="border-right: 1px solid currentColor;">TEW-652BRU_1.00b12.zip</td>
    <td style="border-right: 1px solid currentColor;">Router</td>
    <td style="border-right: 1px solid currentColor;">4</td>
  </tr>
  <tr>
    <td colspan="27" style="border-top: 1px solid currentColor;"></td>
  </tr>
</table>

## Getting Started

### Prerequisites
Make sure the following are installed on your system:
- [Docker](https://docs.docker.com/get-docker/)

---

### Setup & Build

1. **Clone the repository and build the Docker image:**
   ```bash
   git clone https://github.com/alessioizzillo/STAFF.git
   cd STAFF
   ./docker.sh build
   ```

2. **Run the Docker container and set up the environment:**
   ```bash
   ./docker.sh run STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```

3. **Inside the container**, run:
   ```bash
   ./install.sh
   make
   ```

4. **Detach from the container** by pressing:
   ```
   Ctrl-A + D
   ```

5. **Save the current container state** by running:
   ```bash
   docker commit STAFF staff
   ```
6. (Optional) **Remove the container**  by running:
   ```bash
   docker rm -f STAFF
   ```

---

### Create FirmAE Images

To generate the FirmAE image for your firmware:

1. Be sure your firmware is under the directory `firmware/<brand>`

2. Create a docker container with a **bridge network** and attach it:
   ```bash
   ./docker.sh run_bridge STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```

3. Edit the `config.ini` file based on the firmware you want to process:
   ```ini
   [GENERAL]
   mode = check
   firmware = dlink/dap2310_v1.00_o772.bin
   ```

   Use `all` to generate images for the entire dataset:
   ```ini
   [GENERAL]
   mode = check
   firmware = all
   ```

4. Launch the `start.py` script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

5. (Optional) **Remove the container**  by running:
   ```bash
   docker rm -f STAFF
   ```

---

### Capture a new interaction

To capture an interaction for your firmware:

1. Edit the `config.ini` file based on the firmware you want to process and the whitelist/blacklist keywords which will filter in/out some requests (*note*: whitelist has higher priority than blacklist):
   ```ini
   [GENERAL]
   mode = run_capture
   firmware = dlink/dap2310_v1.00_o772.bin

   [CAPTURE]
   whitelist_keywords = POST/PUT/.php/.cgi/.xml
   blacklist_keywords = .gif/.jpg/.png/.css/.js/.ico/.htm/.html
   ```

2. Create a docker container with **host network** and attach it:
   ```bash
   ./docker.sh run STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```

3. Launch the `start.py` script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

4. Wait for firmware booting up, and use a browser or something else to reach the webserver at the indicated IP.

5. All your actions will be recorded into a pcap file.

6. (Optional) **Remove the container**  by running:
   ```bash
   docker rm -f STAFF
   ```

---

### Perform a pre-analysis

To capture an interaction for your firmware:

1. Be sure in `pcap/<brand>/<firmware_name>` there are some pcap files containing an interaction.

2. Edit the `config.ini` file based on the firmware you want to process and the whitelist/blacklist keywords which will filter in/out some requests (*note*: whitelist has higher priority than blacklist):
   ```ini
   [GENERAL]
   mode = pre_analysis
   firmware = dlink/dap2310_v1.00_o772.bin

   [CAPTURE]
   whitelist_keywords = POST/PUT/.php/.cgi/.xml
   blacklist_keywords = .gif/.jpg/.png/.css/.js/.ico/.htm/.html
   ```

2. Create a docker container with **bridge network** and attach it:
   ```bash
   ./docker.sh run_bridge STAFF 0,1     # Replace 0,1 with the CPU cores to assign
   ./docker attach STAFF
   ```
   If the process will be "Killed", it means it exceeded the memory limit during the process. You can modify the script `docker.sh` by increasing the memory limit.

3. Launch the `start.py` script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

---

### Start an experiment

To generate the FirmAE image for your firmware:

1. Edit the `config.ini` file based on the firmware you want to process:
   ```ini
   [GENERAL]
   mode = staff_base     # The available tools are: staff_base/staff_state_aware/aflnet_base/aflnet_state_aware/triforce
   firmware = dlink/dap2310_v1.00_o772.bin

   # Change this params how you want
   [PRE-ANALYSIS]
   subregion_divisor = 10
   min_subregion_len = 3
   delta_threshold = 1.0

   [EMULATION_TRACING]
   include_libraries = 1

   [GENERAL_FUZZING]
   fuzz_tmout = 14400
   timeout = 120
   afl_no_arith = 1
   afl_no_bitflip = 0
   afl_no_interest = 1
   afl_no_user_extras = 1
   afl_no_extras = 1
   afl_calibration = 1
   afl_shuffle_queue = 1

   [AFLNET_FUZZING]
   region_delimiter = \x1A\x1A\x1A\x1A
   proto = http
   region_level_mutation = 1

   [STAFF_FUZZING]
   sequence_minimization = 1
   taint_metrics = rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes
   checkpoint_strategy = 1

   [EXTRA_FUZZING]
   coverage_tracing = taint_block
   stage_max = 1

   ```

2. Launch the image generation script:
   ```bash
   ./docker attach STAFF
   python3 start.py --keep_config 1
   ```

3. Results will be available in:
   - **Fuzzing outputs**: `FirmAE/scratch/<mode>/<image_id>/outputs/`
     - `crashes/`: Crash-inducing inputs
     - `crash_traces/`: Stack traces with taint information
     - `fuzzer_stats`: Real-time fuzzing statistics
     - `plot_data`: Coverage and crash time-series data
   - **Extracted crashes** (after running `extract_crashes.py`): `extracted_crash_out/`

---

### Start a bunch of experiments

You can use `schedule_0.csv` or `schedule_1.csv` to run multiple experiments in parallel across different Docker containers. The CSV structure matches the configuration parameters from `config.ini`:

**CSV Header Structure:**

Row 1 (Category headers):
```
,,,,GENERAL,,PRE-ANALYSIS,,,,EMULATION_TRACING,GENERAL_FUZZING,...
```

Row 2 (Column headers):
```
status,exp_name,container_name,num_cores,mode (M),firmware (F),pre_analysis_id (PAI),subregion_divisor (SD),min_subregion_len (MSL),delta_threshold (DT),include_libraries (IL),map_size_pow2 (MSP),fuzz_tmout (FT),timeout (T),afl_no_arith (ANA),afl_no_bitflip (ANB),afl_no_interest (ANI),afl_no_user_extras (ANU),afl_no_extras (ANE),afl_calibration (AC),afl_shuffle_queue (ASQ),region_delimiter (RD),proto (P),region_level_mutation (RLM),taint_hints_all_at_once (THA),sequence_minimization (SM),taint_metrics (TM),checkpoint_strategy (CS),coverage_tracing (CT),stage_max (SMA)
```

**Column Details:**
- **status**: Automatically filled (empty/running/succeeded/failed)
- **exp_name**: Automatically generated experiment name
- **container_name**: Automatically assigned Docker container name
- **num_cores**: Number of CPU cores to assign (e.g., `1`)
- Remaining columns correspond to parameters from [GENERAL], [PRE-ANALYSIS], [EMULATION_TRACING], [GENERAL_FUZZING], [AFLNET_FUZZING], [STAFF_FUZZING], and [EXTRA_FUZZING] sections

**Example row:**
```csv
,,,1,staff_state_aware,dlink/dap2310_v1.00_o772.bin,0,10,3,1.0,0,25,86400,150,1,0,1,1,1,0,0,,http,1,0,1,number_of_app_tb_pcs,1,block,3
```

To run the experiments in `schedule_0.csv` or `schedule_1.csv`:

To run the experiments into `schedule.csv`:

1. Get the core mapping into `cpu_ids.csv` by launching the following command:
   ```bash
   echo "CPU ID,Physical ID,Logical ID" > cpu_ids.csv; lscpu -p=NODE,CORE,CPU | grep -v '^#' | sort -t',' -k1,1n -k2,2n -k3,3n >> cpu_ids.csv;
   ```

2. Launch the `experiments.py` script:
   ```bash
   python3 experiments.py
   ```

To finally plot the experiments, you need to edit the `plot_params.ini` whose structure is:

   ```ini
   [fixed_params]
   GENERAL.firmware = dlink/dap2310_v1.00_o772.bin
   PRE-ANALYSIS.subregion_divisor = 10
   PRE-ANALYSIS.min_subregion_len = 3
   PRE-ANALYSIS.delta_threshold = 1.0
   EMULATION_TRACING.include_libraries = 1
   GENERAL_FUZZING.fuzz_tmout = 14400
   GENERAL_FUZZING.timeout = 120
   GENERAL_FUZZING.afl_no_arith = 1
   GENERAL_FUZZING.afl_no_bitflip = 0
   GENERAL_FUZZING.afl_no_interest = 1
   GENERAL_FUZZING.afl_no_user_extras = 1
   GENERAL_FUZZING.afl_no_extras = 1
   GENERAL_FUZZING.afl_calibration = 1
   GENERAL_FUZZING.afl_shuffle_queue = 1
   AFLNET_FUZZING.region_delimiter = \x1A\x1A\x1A\x1A
   AFLNET_FUZZING.proto = http
   AFLNET_FUZZING.region_level_mutation = 1
   STAFF_FUZZING.sequence_minimization = 1
   STAFF_FUZZING.taint_metrics = rarest_app_tb_pc/number_of_app_tb_pcs/rarest_process/number_of_processes
   STAFF_FUZZING.checkpoint_strategy = 1
   EXTRA_FUZZING.coverage_tracing = taint_block
   EXTRA_FUZZING.stage_max = 1

   [var_params]
   GENERAL.mode = 

   ```

So, you need to:

1. Set all the fixed parameters and leave blank the parameter you want it to be variable. In the case above, we left blank *mode* which corresponds to the tool name in order to compare results among the other state-of-the-art methods.

2. You can finally (or while running) plot the experiments by launching:
   ```bash
   python3 experiments.py
   ```
3. You will find plots into `exp_out` directory.