INSTRUCTION_PROMPTS = {
    "default_instruction": "Analyze the given code and provide a detailed security report.",
    "instruction_security_analysis_with_cwe": """
As a top-tier security expert, your mission is to analyze the provided source code and its corresponding CWE (Common Weakness Enumeration) information to identify potential security vulnerabilities.

Follow these instructions:
1.  **Understand the CWE**: First, thoroughly review the provided CWE information. It describes the general characteristics, examples, and mitigation methods for this type of vulnerability.
2.  **Analyze the Code**: Scrutinize the provided source code line by line, looking for patterns that match the vulnerability described in the CWE.
3.  **Report Your Findings**: Format your analysis in a JSON object that strictly adheres to the schema specified in `{format_instructions}`.
    *   `"is_vulnerable"`: Explicitly state `true` or `false` to indicate whether you found the CWE vulnerability in the code.
    *   `"vulnerability_reason"`: If you identified a vulnerability, provide a detailed and logical explanation of **why you believe it is vulnerable**. Clearly explain which lines of code violate the CWE principles and how. If you believe it is not vulnerable, briefly explain why.
    *   `"vulnerable_code_snippet"`: Include the exact code snippets that are directly related to the vulnerability. If the vulnerability spans multiple sections, include all of them. If no vulnerability is found, leave this field empty.

Your analysis must be accurate, well-reasoned, and practical, enabling developers to immediately understand and address the issue.

[Source Code to Analyze]
{user_code}

[Reference CWE Information]
{cwe_info}
""",
    "patch_generation_instruction": """
Based on the security analysis provided below, your task is to generate a code patch that fixes the identified vulnerability.
The analysis includes the reason for the vulnerability and the specific code snippet that is vulnerable.

Your output MUST be a JSON object containing the following keys:
- "original_code": A string containing the exact, unmodified vulnerable code snippet from the analysis.
- "patched_code": A string containing the corrected version of the code with the vulnerability fixed. The patch should be minimal and targeted to the issue.
- "explanation": A brief explanation of what was changed and why it fixes the vulnerability.

Do NOT include any other text or explanations outside of the JSON object.

[Security Analysis Result]
{analysis_result_json}
""",
    "summarization_instruction": "Summarize the key functionalities of the given code in three bullet points.",
    "instruction_code_analysis": """
Please analyze the provided source code and provide the following information in English:

1.  **Overall Semantics**: Describe the overall purpose, role, and key responsibilities of this code within the context of a larger application.
2.  **Functional Semantics for Each Function/Method**: For each function or method, provide a detailed description of its functional semantics, including:
    *   **Name**: The name of the function/method.
    *   **Purpose**: What is its primary goal or responsibility?
    *   **Inputs**: What are its parameters and what do they represent?
    *   **Processing**: What are the main logic or key steps it performs?
    *   **Outputs**: What does it return, and what does the return value signify?

The source code to be analyzed is as follows:
```
{user_code}
```
""",
    "instruction_code_improvement_suggestion": """
As a skilled software architect assisting in a peer code review, your task is to suggest concrete improvements for the original code's **readability, maintainability, and performance**, based on the 'Code Functional Analysis' provided below.

Each suggestion should include:
- **The Issue**: Explain what part of the current code could be improved and why.
- **The Suggestion**: Propose a specific methodology or pattern to address the issue.
- **Example Code (Optional)**: If applicable, include a brief code snippet demonstrating how to apply the suggestion.

[Code Functional Analysis]
{analysis_result}
""",
    "instruction_search_related_cwe": """
As a security analyst, your task is to identify potential vulnerability categories based on the provided code analysis.
Read the 'Code Functional Analysis' below and identify a list of CWE (Common Weakness Enumeration) IDs that are most likely to be relevant to this code.

Consider the code's purpose, inputs, and processing logic to make an informed decision.
Your output MUST be a JSON array of strings, where each string is a CWE ID (e.g., "CWE-89", "CWE-79").
Do NOT include any explanations or other text. The response should be only the JSON array.

Example:
["CWE-89", "CWE-20", "CWE-787"]

 [Code Functional Analysis]
{analysis_result}
"""
}
