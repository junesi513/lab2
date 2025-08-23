USER_PROMPTS = {
    "first_request_security_analysis": """Analyze the following code for potential security vulnerabilities. For each vulnerability found, explain the issue and suggest a fix.

    {format_instructions}

    Here is the code:
    {user_code}""",
    "fourth_request_cwe_validation": """As a security expert, your task is to compare two vulnerability descriptions and determine if they refer to the same underlying security weakness.

    1.  **Original Vulnerability Description**: This was identified by an AI analyzing source code.
    2.  **Official CWE Database Description**: This is the official definition from the CWE database for a given CWE-ID.

    Based on your analysis, provide a boolean response (`is_similar`) indicating whether the original description is a valid instance of the weakness described by the CWE database. Also, provide a brief `reasoning` for your decision and a `confidence` score for your judgment.

    Your output MUST be a JSON object that strictly follows this format.
    {format_instructions}

    Here are the descriptions:

    **Original Vulnerability Description:**
    {original_vulnerability_description}

    **Official CWE Database Description:**
    {cwe_database_description}
    """,
    "fifth_request_attack_scenario": """As a security expert and threat analyst, your task is to synthesize the provided information into a final, actionable security report.

    You are given:
    1.  **Vulnerability Analysis**: The initial analysis of a vulnerability found in source code.
    2.  **Confirmed CWE List**: A list of CWEs that have been confirmed to be related to this vulnerability.
    3.  **CWE Relationship Data**: Data showing how different CWEs can relate to each other (e.g., 'ChildOf', 'CanPrecede').

    Based on all this information, perform the following actions and generate a report in the specified JSON format:
    1.  **Identify the Root Cause**: Based on the primary CWEs, explain the fundamental security weakness.
    2.  **Construct an Attack Chain (`cwe_relation`)**: Using the relationship data, describe a logical chain of how these weaknesses could be linked or exploited together. For example: "CWE-A mayCause CWE-B, which canPrecede CWE-C."
    3.  **Create a Vulnerability Scenario**: Write a plausible, concrete narrative of how an attacker might exploit this chain of weaknesses in the context of the original code.

    Your output MUST be a single, valid JSON object that strictly follows this format.
    {format_instructions}

    --- PROVIDED INFORMATION ---

    **1. Initial Vulnerability Analysis:**
    {vulnerability_analysis}

    **2. Confirmed CWE List:**
    {confirmed_cwe_list}

    **3. CWE Relationship Data (in CSV format):**
    ```csv
    {cwe_relationship_data}
    ```
    """,
}