import json
from pathlib import Path
data = json.loads(Path('.codex-plugin/plugin.json').read_text(encoding='utf-8'))
pkg = json.loads(Path('package.json').read_text(encoding='utf-8'))
assert data['name'] == 'dsh-retention-settlement-proof' and data['version'] == pkg['version']
assert data['mcpServers'] == './.mcp.json' and Path('.mcp.json').is_file()
print(json.dumps({'ok': True, 'validator': 'portable-ci'}))
