
import json
import sys

def calculate_delta(nightly_value, branch_value)->float:
    return (branch_value - nightly_value) / nightly_value * 100

def main():
    branch_file = sys.argv[1]
    nightly_file = sys.argv[2]

    with open(nightly_file, 'r') as f:
        nightly_data = json.load(f)
    with open(branch_file, 'r') as f:
        branch_data = json.load(f)
    
    assert nightly_data.keys() == branch_data.keys(), "Keys in the two files do not match."

    lines = []
    lines.append("Comparing proving stats of patch with nightly\n")
    lines.append("|    | Metric                  | Nightly        | Patch           | Change     |")
    lines.append("|----|-------------------------|----------------|------------------|------------|")

    for key in nightly_data.keys():
        nightly_value = nightly_data[key]
        branch_value = branch_data[key]
        delta = calculate_delta(nightly_value, branch_value)

        emoji = "✅" if delta == 0 else ("📈" if delta > 0 else "📉")
        metric = key.replace('_', ' ').title()
        delta_str = f"{delta:+.2f}%"
        lines.append(f"| {emoji} | {metric:<23} | {nightly_value:,} | {branch_value:,} | {delta_str:<9} |")

    with open('comment-body.md', 'w') as f:
        f.write("\n".join(lines))
if __name__ == "__main__":
    main()
