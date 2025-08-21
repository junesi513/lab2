import argparse
import requests
import json
import csv
import os
import re

def get_cwe_data(cwe_id):
    """
    Retrieves CWE data from the MITRE CWE API.

    Args:
        cwe_id (str): The CWE ID to look up.

    Returns:
        dict: The JSON response from the API, or None if an error occurs.
    """
    url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for CWE-{cwe_id}: {e}")
        return None

def clean_string(s):
    """Removes newlines and extra whitespace from a string."""
    if not s:
        return ""
    s = re.sub(r'[\n\r]+', ' ', s)
    s = re.sub(r'\s{2,}', ' ', s)
    return s.strip()

def write_normalized_csv(cwe_data, cwe_id):
    """
    Writes extracted CWE data into three normalized CSV files.
    """
    data_dir = f"data/CWE-{cwe_id}"
    os.makedirs(data_dir, exist_ok=True)

    weakness = cwe_data.get("Weaknesses", [{}])[0]
    if not weakness:
        print("No weakness data found.")
        return

    # 1. Write to cwe_main.csv
    main_filename = f"cwe{cwe_id}_cwe_main.csv"
    main_path = os.path.join(data_dir, main_filename)
    main_fieldnames = ['idx', 'ID', 'Name', 'Description', 'ExtendedDescription']
    main_data = {
        'idx': 0,
        'ID': weakness.get('ID'),
        'Name': clean_string(weakness.get('Name')),
        'Description': clean_string(weakness.get('Description')),
        'ExtendedDescription': clean_string(weakness.get('ExtendedDescription'))
    }
    with open(main_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=main_fieldnames)
        writer.writeheader()
        writer.writerow(main_data)
    print(f"Main CWE data written to {main_path}")

    # 2. Write to RelatedWeakness.csv
    rw_filename = f"cwe{cwe_id}_RelatedWeakness.csv"
    rw_path = os.path.join(data_dir, rw_filename)
    rw_fieldnames = ['cwe_id', 'nature', 'related_cwe_id']
    related_weaknesses = weakness.get('RelatedWeaknesses', [])
    with open(rw_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rw_fieldnames)
        writer.writeheader()
        for item in related_weaknesses:
            writer.writerow({
                'cwe_id': weakness.get('ID'),
                'nature': item.get('Nature'),
                'related_cwe_id': item.get('CweID')
            })
    print(f"Related weaknesses written to {rw_path}")

    # 3. Write to DemonstrativeExample.csv
    de_filename = f"cwe{cwe_id}_DemonstrativeExample.csv"
    de_path = os.path.join(data_dir, de_filename)
    de_fieldnames = ['cwe_id', 'example_id', 'entry_order', 'IntroText', 'Nature', 'Language', 'ExampleCode', 'BodyText']
    demo_examples = weakness.get('DemonstrativeExamples', [])
    
    with open(de_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=de_fieldnames)
        writer.writeheader()
        
        for idx, example in enumerate(demo_examples):
            example_id = example.get('ID', f"GEN-{idx+1}") # Generate an ID if missing
            entries = example.get('Entries', [])
            
            for entry_idx, entry in enumerate(entries):
                row = {
                    'cwe_id': weakness.get('ID'),
                    'example_id': example_id,
                    'entry_order': entry_idx + 1,
                    'IntroText': clean_string(entry.get('IntroText', 'NULL')),
                    'Nature': entry.get('Nature', 'NULL'),
                    'Language': entry.get('Language', 'NULL'),
                    'ExampleCode': entry.get('ExampleCode', 'NULL'),
                    'BodyText': clean_string(entry.get('BodyText', 'NULL'))
                }
                writer.writerow(row)

    print(f"Demonstrative examples written to {de_path}")

def main():
    """
    Main function to parse arguments and save CWE data.
    """
    parser = argparse.ArgumentParser(description="Fetch CWE information and save to normalized CSV files.")
    parser.add_argument("--cwe-id", required=True, help="The CWE ID to look up (e.g., 20).(ex.  python crawling_cwe.py --cwe-id 674)")
    args = parser.parse_args()

    cwe_data = get_cwe_data(args.cwe_id)

    if cwe_data:
        write_normalized_csv(cwe_data, args.cwe_id)

if __name__ == "__main__":
    main()