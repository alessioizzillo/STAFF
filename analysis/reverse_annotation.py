#!/usr/bin/env python3
import json
import struct
import sys
import pytsk3
from collections import defaultdict

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def process_log_file(log_path):
    events = []
    struct_format = "B I I I I B B Q"
    struct_size = struct.calcsize(struct_format)

    with open(log_path, "rb") as f:
        idx = 0
        while True:
            data = f.read(struct_size)
            if len(data) < struct_size:
                break
            unpacked = struct.unpack(struct_format, data)
            event = {
                "index": idx,
                "event": unpacked[0],
                "sink_id": unpacked[1],
                "cov_xxhash": unpacked[2],
                "app_tb_pc": unpacked[3],
                "gpa": unpacked[4],
                "op_name": unpacked[5],
                "value": unpacked[6],
                "inode": unpacked[7]
            }
            events.append(event)
            idx += 1
    return events

def build_inode_to_path_map(fs_image_path):
    inode_to_path = {}
    img = pytsk3.Img_Info(fs_image_path)
    fs = pytsk3.FS_Info(img)

    def walk_dir(directory, path="/"):
        for entry in directory:
            if not hasattr(entry, "info") or not hasattr(entry.info, "name"):
                continue
            if entry.info.name.name in [b".", b".."]:
                continue
            try:
                inode = entry.info.meta.addr
                name = entry.info.name.name.decode("utf-8", errors="ignore")
                full_path = path + name
                inode_to_path[inode] = full_path
                if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    subdir = fs.open_dir(inode=inode)
                    walk_dir(subdir, full_path + "/")
            except Exception:
                continue

    root_dir = fs.open_dir("/")
    walk_dir(root_dir, "/")
    return inode_to_path

def collect_inode_pc_tuples(events, sink_id, substring_filter):
    inode_pc_with_pos = []
    filtered = [e for e in events if e["sink_id"] == sink_id]

    groups = []
    for op in [0, 1]:
        current_str = []
        current_inodes = set()
        last_gpa = None
        first_event_idx = None

        for e in filtered:
            if e["op_name"] != op:
                continue
            if last_gpa is not None and e["gpa"] != last_gpa + 1:
                if current_str:
                    s = "".join(current_str)
                    if substring_filter in s:
                        groups.append((first_event_idx, set(current_inodes)))
                current_str = []
                current_inodes = set()
                first_event_idx = None

            if first_event_idx is None:
                first_event_idx = e["index"]

            current_str.append(chr(int(e["value"])))
            current_inodes.add(("store" if e["op_name"] else "load",
                                e["inode"], hex(e["app_tb_pc"])))
            last_gpa = e["gpa"]

        if current_str:
            s = "".join(current_str)
            if substring_filter in s:
                groups.append((first_event_idx, set(current_inodes)))

    groups.sort(key=lambda g: g[0])

    position_number = 1
    for _, inode_pc_set in groups:
        for t in inode_pc_set:
            inode_pc_with_pos.append((t[0], t[1], t[2], position_number))
        position_number += 1

    inode_pc_with_pos.sort(key=lambda x: x[3])
    return inode_pc_with_pos

def get_infos_a(data, region_id, start_offset, count):
    try:
        region = data[region_id]
    except IndexError:
        sys.exit(f"Error: region_id {region_id} not found.")

    elements = region[1]
    infos_a_set = set()
    for i in range(start_offset, min(start_offset + count, len(elements))):
        element = elements[i]
        _, _, infos_a, _ = element
        for entry in infos_a:
            if isinstance(entry, list):
                infos_a_set.add(tuple(entry))
    return infos_a_set

def parse_args(argv):
    params = {}
    for arg in argv[1:]:
        if "=" not in arg:
            sys.exit(f"Invalid argument '{arg}', must be in form key=value")
        k, v = arg.split("=", 1)
        params[k.strip()] = v.strip()
    return params

def main():
    params = parse_args(sys.argv)

    required = ["log", "fs", "json", "region", "offset", "count", "sinks", "substr"]
    for r in required:
        if r not in params:
            sys.exit(f"Missing required parameter: {r}")

    log_path = params["log"]
    fs_image = params["fs"]
    json_file = params["json"]
    region_id = int(params["region"])
    offset = int(params["offset"])
    count = int(params["count"])
    sink_ids = [int(s) for s in params["sinks"].split(",")]
    substring_filter = params["substr"]

    with open(json_file, "r") as f:
        data = json.load(f)
    infos_a_set = get_infos_a(data, region_id, offset, count)

    events = process_log_file(log_path)
    inode_map = build_inode_to_path_map(fs_image)

    summary = defaultdict(lambda: defaultdict(lambda: {"green": 0, "red": 0}))

    for sink_id in sink_ids:
        inode_pc_set = collect_inode_pc_tuples(events, sink_id, substring_filter)

        for op_name, inode, pc, pos in inode_pc_set:
            module_name = inode_map.get(inode, f"<unknown_inode:{inode}>")
            check_tpl = (inode, int(pc, 16))
            color = "green" if check_tpl in infos_a_set else "red"
            summary[sink_id][module_name][color] += 1

    # ---- Print table ----
    print("\nSummary per module and sink_id:")
    for sink_id in sink_ids:
        print(f"\nSink ID {sink_id}:")
        print(f"{'Module':50} {'Present (green)':>15} {'Filtered (red)':>15}")
        print("-" * 85)
        for module, counts in summary[sink_id].items():
            g = counts["green"]
            r = counts["red"]
            print(f"{module:50} {GREEN}{g:>15}{RESET} {RED}{r:>15}{RESET}")

if __name__ == "__main__":
    main()
