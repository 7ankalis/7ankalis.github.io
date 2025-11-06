import re
import sys
import os

def migrate_markdown_to_nextjs(input_filepath):
    """
    Migrates Jekyll-style markdown elements (Chirpy theme) to Next.js/MDX
    components, handles dollar sign escaping, and outputs to 'migrated.mdx'.
    """
    try:
        with open(input_filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_filepath}' not found.")
        return
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return

    # --- 1. Code Block Migration ---
    # Regex to find:
    # 1. Start of code block: ```language (non-greedy)
    # 2. The code content itself (non-greedy, can span multiple lines)
    # 3. End of code block: ```
    codeblock_pattern = re.compile(
        r'```(\w+)\s*\n(.*?)\n```',
        re.DOTALL  # Allows '.' to match newlines
    )

    def replace_codeblock(match):
        language = match.group(1).strip()
        code_content = match.group(2).strip()

        # FIX: The braces surrounding the JavaScript object ({{[...]}}) must be
        # doubled ({{ and }}) within the f-string to be treated as literals.
        return (
            f'<CodeBlock\n'
            f'  lineNumbers\n'
            f'  highlight="3,11,12"\n'
            f'  fullscreenButton\n\n'
            f'  codes=\n'
            # FIX: Start of JS object: {[{ -> {{[{{
            f'  {{[{{\n'
            f'  language: "{language}",\n'
            f'  label: "{language.capitalize()}",\n'
            f'  code:\n'
            # FIX: End of JS object: }]} -> }}]}}\n
            f'  `{code_content}`}}}}\n'
            f'/>'
        )

    content = codeblock_pattern.sub(replace_codeblock, content)

    # --- 2. Feedback Block Migration ---
    # Regex to find:
    # 1. Start of block: >text! (non-greedy, captures the quoted text)
    # 2. The {: .prompt-<something> } line (non-greedy, captures the 'something')
    feedback_pattern = re.compile(
        r'^>\s*(.*?)\s*\n\{\s*:\s*\.prompt-(\w+)\s*\}',
        re.MULTILINE | re.DOTALL
    )

    def replace_feedback(match):
        title = match.group(1).strip()
        variant_type = match.group(2).strip()

        # Map 'tip' to 'success', 'danger' to 'dangerous', others stay the same
        variant_map = {
            'tip': 'success',
            'warning': 'warning',
            'danger': 'dangerous'
        }
        variant = variant_map.get(variant_type, variant_type)

        # Handle specific 'tip' description as requested
        description = "Your action has been completed successfully."
        if variant_type == 'tip':
            description = "whatever."

        return (
            f'<Feedback \n'
            f'  variant="{variant}" \n'
            f'  title="{title}" \n'
            f'  description="{description}"\n'
            f'/>'
        )

    content = feedback_pattern.sub(replace_feedback, content)

    # --- 3. Dollar Sign Escaping ---
    content = re.sub(r'(?<!\\)\$', r'\\$', content)

    # --- Output to new file ---
    output_filepath = 'migrated.mdx'
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Migration successful! Output written to '{output_filepath}'")
    except Exception as e:
        print(f"An error occurred while writing the file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python migrate_chirpy.py <input_file.md>")
        sys.exit(1)

    input_file = sys.argv[1]
    migrate_markdown_to_nextjs(input_file)
