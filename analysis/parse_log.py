import struct
import json
import sys

def process_log_file(log_path):
    events = []
    struct_format = "B I I I I B B Q"
    struct_size = struct.calcsize(struct_format)

    with open(log_path, "rb") as f:
        while True:
            data = f.read(struct_size)
            if len(data) < struct_size:
                break

            unpacked = struct.unpack(struct_format, data)
            event = {
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

    return events


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <log_file> <input_json> <sink_id>")
        sys.exit(1)

    log_path = sys.argv[1]
    json_path = sys.argv[2]
    sink_id = int(sys.argv[3])

    events = process_log_file(log_path)

    with open(json_path, "r") as f:
        pcs_data = json.load(f)

    pcs = pcs_data.get("pcs", [])

    results = set()
    for inode, pc in pcs:
        for e in events:
            if e["sink_id"] == sink_id and e["inode"] == inode and e["app_tb_pc"] == pc:
                results.add(("store" if e["op_name"] == "1" else "load", hex(inode), hex(pc)))

    results_list = sorted(results)

    print(results_list)


if __name__ == "__main__":
    main()
