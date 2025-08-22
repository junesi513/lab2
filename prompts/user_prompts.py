USER_PROMPTS = {
    "question_hello": "Hello, what is your name?",
    "request_python_example": "Please provide a simple Python code example for reading a file.",
    "request_code_review": "Please review the following Python code and suggest improvements:\n\n```python\ndef add(a, b):\n    return a+b\n```",
    "request_security_analysis": "Please analyze the security of the following code snippet.",
    "task_create_function": "Write a Python function that takes a list of integers and returns the sum of all even numbers.",
    "task_refactor_code": "The following code is inefficient. Please refactor it to improve performance.",
    "first_request_security_analysis": """Analyze the following code for potential security vulnerabilities. For each vulnerability found, explain the issue and suggest a fix.

    {format_instructions}

    Here is the code:
    {user_code}""",
    "second_request_security_analysis": """Given the following security analysis result in JSON format, your task is to perform two actions for each vulnerability:
1. Extract important technical keywords from the 'CWE-Type','vulnerability' and 'explanation' fields.
2. Identify the most relevant CWE-ID for the vulnerability. Provide the ID in the format "CWE-ID".

Your output MUST be a JSON object that strictly follows this format.
{format_instructions}

Here is the security analysis result:
{first_analysis_result}
""",
    "third_request_cwe_validation": """As a security expert, your task is to compare two vulnerability descriptions and determine if they refer to the same underlying security weakness.

1.  **Original Vulnerability Description**: This was identified by an AI analyzing source code.
2.  **Official CWE Database Description**: This is the official definition from the CWE database for a given CWE-ID.

Based on your analysis, provide a boolean response (`is_similar`) indicating whether the original description is a valid instance of the weakness described by the CWE database. Also, provide a brief `reasoning` for your decision.

Your output MUST be a JSON object that strictly follows this format.
{format_instructions}

Here are the descriptions:

**Original Vulnerability Description:**
{original_vulnerability_description}

**Official CWE Database Description:**
{cwe_database_description}
""",
    "fourth_request_double_check": """As a security expert, your task is to perform a detailed comparison between an AI-generated vulnerability description and the official, extended descriptions from the CWE database.

1.  **Original Vulnerability Description**: Identified by an AI analyzing source code.
2.  **Official CWE Descriptions**: The official 'Description' and 'Extended Description' from the CWE database.

Based on a thorough analysis of all provided texts, determine if the original description genuinely represents the core weakness detailed in the official CWE descriptions.

Your output MUST be a JSON object that strictly follows this format.
{format_instructions}

Here are the details:

**Original Vulnerability Description:**
{original_vulnerability_description}

**Official CWE Descriptions:**
{cwe_description}
""",
    "fifth_request_relationship_analysis": """As a security expert, your task is to validate a potential relationship between two CWE weaknesses in the context of a specific vulnerability found in source code.

You will be given:
1.  **Original Vulnerability Description**: The specific weakness identified by an AI in the code.
2.  **Source CWE Description**: The official description of the parent/source CWE.
3.  **Target CWE Description**: The official description of a CWE that is potentially related to the source.
4.  **Relationship Type**: The nature of the link between the source and target CWE (e.g., 'ChildOf', 'CanAlsoBe').

To guide your analysis, use the following definitions for relationship types:
- **ParentOf**: Use this to state that a vulnerability is a more abstract, broader category for another.
  - *Example*: CWE-20 (Improper Input Validation) is a ParentOf CWE-1284 (Improper Validation of Specified Quantity in Input).
- **ChildOf**: Use this to show that a vulnerability is a specific example or subtype of another.
  - *Example*: CWE-1284 is a ChildOf CWE-20.
- **PeerOf**: Use this to indicate that two vulnerabilities are on a similar level and are conceptually related or similar.
  - *Example*: CWE-20 is a PeerOf CWE-345 (Insufficient Verification of Data Authenticity).
- **CanPrecede**: Use this to explain that one vulnerability can be a prerequisite or lead to another. This is for showing a potential attack chain.
  - *Example*: CWE-20 can precede CWE-74 (Improper Neutralization of Special Elements in Output used by a Downstream Component).

Analyze all information and determine if, in the context of the *original vulnerability*, the stated relationship is logically valid. In addition to your validation, provide a `confidence` score between 0.0 and 1.0 representing your certainty. A score of 1.0 means you are absolutely certain the relationship is valid in this context, while 0.0 means it is not valid at all.

Your output MUST be a JSON object that strictly follows this format.
{format_instructions}

**Analysis Details:**

*   **Original Vulnerability Description:**
    `{original_vulnerability_description}`

*   **Source CWE (Parent/Source):**
    `{source_cwe_description}`

*   **Target CWE (Child/Related):**
    `{target_cwe_description}`

*   **Stated Relationship (`{relationship_type}`):** Does the Source CWE have a `{relationship_type}` relationship with the Target CWE that is relevant to the original vulnerability?
    """,
    "fifth_request_attack_scenario": """As a security expert, your task is to synthesize information from multiple analysis steps to create plausible attack scenarios for the given source code.

You are provided with:
1.  **Source Code**: The original code being analyzed.
2.  **Initial Vulnerability Analysis**: A list of potential vulnerabilities identified in the code.
3.  **Validated Attack Chains**: A list of validated, multi-step CWE relationship chains that represent potential attack paths (e.g., "CWE-20 -> CWE-74 -> CWE-123").

Based on all this information, describe one or more detailed attack scenarios. Each scenario must include:
- A title and a step-by-step description.
- The specific CWE relationship chain that enables the scenario (e.g., "CWE-20 -> CWE-74 -> CWE-123").
- A `confidence` score and `severity` rating based on the guidelines below.

**CONFIDENCE SCORING:**
- 0.9-1.0: Certain exploit path identified, tested if possible
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Don't report (too speculative)

**SEVERITY GUIDELINES:**
- **HIGH**: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- **MEDIUM**: Vulnerabilities requiring specific conditions but with significant impact
- **LOW**: Defense-in-depth issues or lower-impact vulnerabilities

**FINAL REMINDER:**
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a PR review.

Your output MUST be a JSON object that strictly follows this format.
{format_instructions}

**Provided Information:**

**1. Source Code:**
```
{user_code}
```

**2. Initial Vulnerability Analysis:**
```json
{step1_analysis_result}
```

**3. Validated CWE Relationships:**
```json
{cwe_relation}
```
""",
}