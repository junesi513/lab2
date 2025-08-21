import argparse
import csv
import os
import json
import openai
from collections import defaultdict
from openai import OpenAI
import re

def read_examples(cwe_id):
    """
    Reads demonstrative examples from the CSV file for a given CWE ID.
    """
    # NOTE: The path is based on the output of crawling_cwe.py
    file_path = f"data/CWE-{cwe_id}/cwe{cwe_id}_DemonstrativeExample.csv"
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return None

    examples = defaultdict(list)
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                examples[row['example_id']].append(row)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
        
    return examples

def call_gpt_for_fix(example_id, prompt_text, model, client):
    """
    Calls the OpenAI GPT model to suggest a fix for the given prompt.
    """
    print(f"--- Calling GPT for Example ID: {example_id} ---")

    system_prompt = f"""You are a security programming expert. Analyze the following code example and provide a fixed version of the code that addresses the described vulnerability.

Your output MUST be a single, valid JSON object. Do not include any text or formatting outside of the JSON object.
The JSON object must have the following structure:
{{
  "example_id": "{example_id}",
  "fixed_code": "The corrected code block as a single JSON string. All special characters, backslashes, and newlines must be properly escaped.",
  "description": "A detailed explanation of the vulnerability and how the fix addresses it, as a single JSON string. All special characters, backslashes, and newlines must be properly escaped."
}}

Ensure your response is a raw JSON object, starting with `{{` and ending with `}}`.
"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_text}
            ],
            timeout=30.0,
        )
        suggestion = response.choices[0].message.content
        return suggestion
    except Exception as e:
        error_message = f"Error calling OpenAI API for {example_id}: {e}"
        print(error_message)
        return json.dumps({"example_id": example_id, "error": error_message})


def main():
    """
    Main function to parse arguments and process demonstrative examples.
    """
    parser = argparse.ArgumentParser(description="Process CWE demonstrative examples and generate fixes.")
    parser.add_argument("--cwe-id", required=True, help="The CWE ID to process (e.g., 20).")
    args = parser.parse_args()

    cwe_id = args.cwe_id
    examples_by_id = read_examples(cwe_id)

    if not examples_by_id:
        print("No examples found to process.")
        return

    # --- API Client Setup ---
    api_key = None
    model = "gpt-4" # Default model
    api_base = None # Default API base

    try:
        with open('./config.json', 'r') as f:
            config = json.load(f)
        api_key = config.get("OPENAI_API_KEY")
        chatgpt_config = config.get("chatgpt", {})
        model = chatgpt_config.get("model", model)
        api_base = chatgpt_config.get("api_base", api_base)
        if api_key and api_key == "TODO":
            api_key = None
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        print("Error: API key not found in config.json or OPENAI_API_KEY environment variable.")
        return
            
    client = OpenAI(api_key=api_key, base_url=api_base)
    # --- End of API Client Setup ---
        
    all_fixes = []
    print(f"Processing CWE-{cwe_id} examples one by one...\n")
    for example_id, entries in examples_by_id.items():
        
        prompt_parts = []
        for entry in entries:
            intro_text = entry.get('IntroText')
            if intro_text and intro_text.strip() != 'NULL':
                prompt_parts.append(f"IntroText: {intro_text.strip()}")
            
            language = entry.get('Language')
            if language and language.strip() != 'NULL':
                prompt_parts.append(f"Language: {language.strip()}")
            
            example_code = entry.get('ExampleCode')
            if example_code and example_code.strip() != 'NULL':
                prompt_parts.append(f"ExampleCode:\n{example_code.strip()}")
                
            body_text = entry.get('BodyText')
            if body_text and body_text.strip() != 'NULL':
                prompt_parts.append(f"BodyText: {body_text.strip()}")
        
        if not prompt_parts:
            print(f"--- Skipping Example ID: {example_id} (no content) ---\n")
            continue
            
        full_prompt = "\n\n".join(prompt_parts)
        
        raw_response = call_gpt_for_fix(example_id, full_prompt, model, client)
        
        try:
            # Find the JSON block within the raw response using regex
            # This helps to clean up cases where the model adds extra text like ```json
            json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
            if json_match:
                json_string = json_match.group(0)
                fix_data = json.loads(json_string)
                all_fixes.append(fix_data)
                print(f"--- Successfully processed and parsed fix for {example_id} ---")
            else:
                raise json.JSONDecodeError("No JSON object found in response", raw_response, 0)

        except json.JSONDecodeError as e:
            print(f"--- Failed to parse JSON response for {example_id} ---")
            print("Raw Response:", raw_response)
            all_fixes.append({"example_id": example_id, "error": f"Failed to parse JSON: {e}", "raw_response": raw_response})
        print("---------------------------------------\n")

    # Save all collected fixes to a single JSON file
    output_dir = f"data/CWE-{cwe_id}"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"cwe{cwe_id}_FixedExample.json")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(all_fixes, f, ensure_ascii=False, indent=4)

    print(f"All fixes have been saved to {output_path}")


if __name__ == "__main__":
    main() 