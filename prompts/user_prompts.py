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

Analyze all information and determine if, in the context of the *original vulnerability*, the stated relationship is logically valid. For example, does the nature of the original vulnerability mean that the source CWE could indeed lead to or be a type of the target CWE?

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
3.  **Validated CWE Relationships**: A knowledge graph showing how different types of weaknesses (CWEs) can be chained together.

Based on all this information, describe one or more detailed attack scenarios. Each scenario should explain how an attacker could exploit one or more of the identified vulnerabilities, potentially chaining them together as suggested by the CWE relationships, to compromise the application.

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