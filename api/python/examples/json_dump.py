import lief
import json
import sys

if len(sys.argv) != 2:
    print("Usage: {} <file>".format(sys.argv[0]))
    sys.exit(1)


obj = lief.parse(sys.argv[1])

json_data = json.loads(lief.to_json(obj))

print(json.dumps(json_data, sort_keys = True, indent = 4))
