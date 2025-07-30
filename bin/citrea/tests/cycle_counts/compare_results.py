
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
    results = []
    for key in nightly_data.keys():
        nightly_value = nightly_data[key]
        branch_value = branch_data[key]
        delta = calculate_delta(nightly_value, branch_value)
        if delta == 0:
            results.append(f"✅ {key.replace('_', ' ').title()} is the same: {nightly_value}")
        else:
            emoji = "📈" if delta > 0 else "📉"
            results.append(f"{emoji} {key.replace('_', ' ').title()} differ {nightly_value} vs {branch_value} ({delta:+.2f}%)")

    print("Comparing proving stats of patch with nightly")
    print("\n".join(results))
if __name__ == "__main__":
    main()
