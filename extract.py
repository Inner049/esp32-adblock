import re, json

transcript_path = r'C:\Users\inner\.gemini\antigravity-ide\brain\fa149db4-1103-4e48-ac5d-d5157d15ed59\.system_generated\logs\transcript_full.jsonl'

with open(transcript_path, 'r', encoding='utf-8') as f:
    for line in f:
        if 'Commercial version: WiFi setup wizard' in line and 'write_to_file' in line:
            data = json.loads(line)
            for call in data.get('tool_calls', []):
                args_str = call.get('function', {}).get('arguments', '{}')
                if isinstance(args_str, str):
                    try:
                        args = json.loads(args_str)
                        if 'CodeContent' in args and 'Commercial version: WiFi setup wizard' in args['CodeContent']:
                            with open('src/main.cpp', 'w', encoding='utf-8') as mf:
                                mf.write(args['CodeContent'])
                            print('Restored successfully!')
                            exit(0)
                    except:
                        pass
print('Not found')
