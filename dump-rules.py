from suricataparser import parse_file
import sys
rules = parse_file(sys.argv[1])
import json
with open(f'suricata.json', 'w', encoding='utf-8') as f:
	f.write(json.dumps(rules, default=vars)) 