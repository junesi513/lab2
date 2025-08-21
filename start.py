"""
Input vulnerable code
Functional semantics
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import argparse
import json
import datetime
import re
import logging
import glob
import subprocess
from dotenv import load_dotenv

import pandas as pd
from typing import List
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.chat_models import ChatOllama
from langchain.output_parsers import PydanticOutputParser, OutputFixingParser
from langchain_core.output_parsers import StrOutputParser
from langchain_core.exceptions import OutputParserException
from langchain_core.prompts import PromptTemplate, ChatPromptTemplate

from prompts.user_prompts import USER_PROMPTS
from src.chain import create_security_chain
from prompts.system_prompts import SYSTEM_PROMPTS
from prompts.instruction_prompts import INSTRUCTION_PROMPTS


def setup_debug_logger(model_name: str):
    """Sets up a logger for debug mode."""
    logger = logging.getLogger('debug_logger')
    logger.setLevel(logging.INFO)

    # Prevent adding multiple handlers if called more than once
    if logger.hasHandlers():
        return logger

    # Create debug directory
    debug_log_dir = os.path.join("logs", "debug")
    os.makedirs(debug_log_dir, exist_ok=True)

    # Formatters
    console_formatter = logging.Formatter('%(message)s')
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(console_formatter)
    logger.addHandler(ch)

    # File handler
    safe_model_name = model_name.replace(":", "_").replace("/", "_")
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    log_file_path = os.path.join(debug_log_dir, f"debug-{safe_model_name}-{date_str}.log")
    
    fh = logging.FileHandler(log_file_path, encoding='utf-8')
    fh.setLevel(logging.INFO)
    fh.setFormatter(file_formatter)
    logger.addHandler(fh)

    return logger

def log_llm_interaction(model_name: str, request_data: dict, response_data: dict or str):
    """Logs the interaction with the LLM to a JSON file."""
    try:
        # Replace special characters in model name for a safe file path
        safe_model_name = model_name.replace(":", "_").replace("/", "_")
        
        # Set log directory path based on date
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_dir = os.path.join("logs", safe_model_name, date_str)
        os.makedirs(log_dir, exist_ok=True)
        
        # Set log file name based on timestamp
        timestamp_str = datetime.datetime.now().strftime("%H-%M-%S-%f")
        log_file_path = os.path.join(log_dir, f"{timestamp_str}.json")
        
        # Construct log content
        log_content = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": model_name,
            "request": request_data,
            "response": response_data,
        }
        
        # Save as JSON file
        with open(log_file_path, 'w', encoding='utf-8') as f:
            json.dump(log_content, f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"\n[Logging Error] An issue occurred while writing the log file: {e}")

class Vulnerability(BaseModel):
    vulnerability: str = Field(description="Description of the vulnerability")
    explanation: str = Field(description="Explanation of why this is a vulnerability")
    fix: str = Field(description="Suggested fix for the vulnerability")

class Vulnerabilities(BaseModel):
    vulnerabilities: List[Vulnerability] = Field(description="A list of vulnerabilities found in the code")

class KeywordResult(BaseModel):
    vulnerability: str = Field(description="Original vulnerability description")
    keywords: List[str] = Field(description="A list of extracted keywords")
    cwe_id: str = Field(description="The most relevant CWE-ID for the vulnerability, e.g., 'CWE-74'")

class KeywordList(BaseModel):
    vulnerability_keywords: List[KeywordResult] = Field(description="A list of vulnerabilities with their keywords and CWE-IDs")

class CweValidationResult(BaseModel):
    is_similar: bool = Field(description="True if the original vulnerability description is a valid instance of the CWE, False otherwise.")
    reasoning: str = Field(description="A brief justification for the is_similar decision.")

class RelationshipValidationResult(BaseModel):
    is_relationship_valid: bool = Field(description="True if the relationship between the CWEs is logically valid in the context of the original vulnerability.")
    relationship: str = Field(description="A descriptive string of the relationship, e.g., 'CWE-20 Can Lead To CWE-704'.")
    justification: str = Field(description="A brief explanation for the validation decision.")
    
class AttackScenario(BaseModel):
    scenario_title: str = Field(description="A concise title for the attack scenario.")
    scenario_description: str = Field(description="A detailed step-by-step description of how the attack could be executed.")

class AttackScenarios(BaseModel):
    attack_scenarios: List[AttackScenario] = Field(description="A list of potential attack scenarios based on the analysis.")


def get_llm(model_str: str, api_keys: dict):
    """Returns the appropriate LLM instance based on the model string and API keys."""
    
    if model_str.startswith('ollama:'):
        model_name = model_str.split(':', 1)[1]
        return ChatOllama(model=model_name)
    elif model_str.startswith('gemini-'):
        return ChatGoogleGenerativeAI(model=model_str, google_api_key=api_keys.get("GEMINI_API_KEY"))
    elif model_str.startswith('gpt-'):
        return ChatOpenAI(model=model_str, openai_api_key=api_keys.get("OPENAI_API_KEY"))
    else:
        raise ValueError(f"Unsupported model: {model_str}")

def load_api_keys():
    """Loads API keys from config.json or environment variables."""
    config_file = 'config.json'
    api_keys = {}

    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            api_keys["OPENAI_API_KEY"] = config.get("OPENAI_API_KEY")
            api_keys["GEMINI_API_KEY"] = config.get("GEMINI_API_KEY")
    else:
        load_dotenv()
        api_keys["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
        api_keys["GEMINI_API_KEY"] = os.getenv("GEMINI_API_KEY")
        
    return api_keys

def run_chat_task(llm, model_name, system_id, user_id, logger=None):
    """Performs a general chat task."""
    system_prompt = SYSTEM_PROMPTS.get(system_id)
    if not system_prompt:
        raise ValueError(f"Could not find ID '{system_id}' in system_prompts.py.")

    user_prompt = USER_PROMPTS.get(user_id)
    if not user_prompt:
        raise ValueError(f"Could not find ID '{user_id}' in user_prompts.py.")

    prompt_template = PromptTemplate(
        template="""
{system_prompt}

{user_prompt}
""",
        input_variables=["system_prompt", "user_prompt"],
    )
    chain = prompt_template | llm
    
    print(f"[System ID: {system_id}] > {system_prompt}")
    print(f"[User ID: {user_id}] > {user_prompt}\n")
    
    if logger:
        logger.info("\n==================== LLM REQUEST ====================")
        logger.info(f"TASK: chat")
        logger.info(f"SYSTEM PROMPT: {system_prompt}")
        logger.info(f"USER PROMPT:\n{user_prompt}")
        logger.info("=====================================================")

    response = chain.invoke({"system_prompt": system_prompt, "user_prompt": user_prompt})
    
    if logger:
        logger.info("\n==================== LLM RESPONSE ===================")
        response_content_for_log = response.content if hasattr(response, 'content') else str(response)
        logger.info(response_content_for_log)
        logger.info("=====================================================")

    # Add logging
    request_data = {
        "system_prompt_id": system_id, "system_prompt": system_prompt,
        "user_prompt_id": user_id, "user_prompt": user_prompt
    }
    response_content = response.content if hasattr(response, 'content') else response
    log_llm_interaction(model_name, request_data, response_content)
    
    print("[Response]")
    if hasattr(response, 'content'):
        print(response.content)
    else:
        print(response)

def run_batch_chat_task(llm, model_name, logger=None):
    """Performs a batch task for all system/user prompt combinations."""
    print("--- Starting batch test for all prompt combinations. ---")
    
    if not SYSTEM_PROMPTS or not USER_PROMPTS:
        print("[Warning] System or user prompts are empty, skipping batch test.")
        return

    for system_id, system_prompt in SYSTEM_PROMPTS.items():
        for user_id, user_prompt in USER_PROMPTS.items():
            print(f"\n=================================================")
            print(f"Running: [System ID: {system_id}] | [User ID: {user_id}]")
            print(f"=================================================\n")
            
            try:
                # Create and run a chain for each combination
                prompt_template = PromptTemplate(
                    template="""
{system_prompt}

{user_prompt}
""",
                    input_variables=["system_prompt", "user_prompt"],
                )
                chain = prompt_template | llm

                if logger:
                    logger.info("\n==================== LLM REQUEST ====================")
                    logger.info(f"TASK: batch_chat (System: {system_id}, User: {user_id})")
                    logger.info(f"SYSTEM PROMPT: {system_prompt}")
                    logger.info(f"USER PROMPT:\n{user_prompt}")
                    logger.info("=====================================================")
                
                response = chain.invoke({"system_prompt": system_prompt, "user_prompt": user_prompt})

                if logger:
                    logger.info("\n==================== LLM RESPONSE ===================")
                    response_content_for_log = response.content if hasattr(response, 'content') else str(response)
                    logger.info(response_content_for_log)
                    logger.info("=====================================================")
                
                # Add logging
                request_data = {
                    "system_prompt_id": system_id, "system_prompt": system_prompt,
                    "user_prompt_id": user_id, "user_prompt": user_prompt
                }
                response_content = response.content if hasattr(response, 'content') else response
                log_llm_interaction(model_name, request_data, response_content)
                
                print(f"[System] > {system_prompt}")
                print(f"[User] > {user_prompt}\n")
                print("[Response]")
                if hasattr(response, 'content'):
                    print(response.content)
                else:
                    print(response)
            except Exception as e:
                print(f"An error occurred while running combination '{system_id}' and '{user_id}': {e}")


def run_code_chat_task(llm, model_name, code_file_pattern, system_id, user_id, logger=None):
    """Reads code from files matching a glob pattern and performs a chat task."""
    
    # Pydantic model for the desired output
    class Vulnerability(BaseModel):
        vulnerability: str = Field(description="Description of the vulnerability")
        explanation: str = Field(description="Explanation of why this is a vulnerability")
        fix: str = Field(description="Suggested fix for the vulnerability")

    class Vulnerabilities(BaseModel):
        vulnerabilities: list[Vulnerability] = Field(description="A list of vulnerabilities found in the code")

    parser = PydanticOutputParser(pydantic_object=Vulnerabilities)

    try:
        # Expand user home directory and resolve glob pattern
        expanded_path = os.path.expanduser(code_file_pattern)
        file_paths = glob.glob(expanded_path)

        if not file_paths:
            print(f"[Error] No files found matching pattern: {code_file_pattern}")
            return

        user_code_parts = []
        print("Analyzing the following files:")
        for file_path in file_paths:
            print(f"- {file_path}")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            header = f"--- START OF FILE: {os.path.basename(file_path)} ---\n"
            footer = f"\n--- END OF FILE: {os.path.basename(file_path)} ---"
            user_code_parts.append(f"{header}{content}{footer}")
        
        user_code = "\n\n".join(user_code_parts)

    except Exception as e:
        print(f"[Error] Failed to read code files: {e}")
        return

    system_prompt = SYSTEM_PROMPTS.get(system_id)
    if not system_prompt:
        raise ValueError(f"Could not find ID '{system_id}' in system_prompts.py.")

    user_prompt_template = USER_PROMPTS.get(user_id)
    if not user_prompt_template:
        raise ValueError(f"Could not find ID '{user_id}' in user_prompts.py.")
        
    # Format the user prompt with the code
    user_prompt = user_prompt_template.format(
        user_code=user_code, 
        format_instructions=parser.get_format_instructions()
    )

    prompt_template = PromptTemplate(
        template="""
{system_prompt}

{user_prompt}
""",
        input_variables=["system_prompt", "user_prompt"],
    )
    
    # The PydanticOutputParser is now part of the chain
    chain = prompt_template | llm | parser
    
    print(f"[System ID: {system_id}] > {system_prompt}")
    print(f"[User ID: {user_id}]")
    print(f"[Code File Pattern: {code_file_pattern}]\n")
    
    if logger:
        logger.info("\n==================== LLM REQUEST ====================")
        logger.info(f"TASK: code_chat")
        logger.info(f"SYSTEM PROMPT: {system_prompt}")
        logger.info(f"USER PROMPT:\n{user_prompt}")
        logger.info("=====================================================")

    try:
        response = chain.invoke({"system_prompt": system_prompt, "user_prompt": user_prompt})
        
        if logger:
            logger.info("\n==================== LLM RESPONSE ===================")
            logger.info(response.json())
            logger.info("=====================================================")

        request_data = {
            "system_prompt_id": system_id, "system_prompt": system_prompt,
            "user_prompt_id": user_id, "user_prompt": user_prompt
        }
        log_llm_interaction(model_name, request_data, response.dict())
        
        print("[Response]")
        print(json.dumps(response.dict(), indent=2, ensure_ascii=False))
        
    except OutputParserException as e:
        print(f"\n[Parsing Error] Failed to parse LLM response: {e}")
        # Log the raw, unparseable output
        raw_output = str(e.llm_output) if hasattr(e, 'llm_output') else str(e)
        request_data = {
            "system_prompt_id": system_id, "system_prompt": system_prompt,
            "user_prompt_id": user_id, "user_prompt": user_prompt
        }
        log_llm_interaction(model_name, request_data, {"error": "OutputParserException", "raw_output": raw_output})
        print("\n--- LLM Raw Response ---")
        print(raw_output)


def run_full_analysis_pipeline(llm, model_name, code_file_pattern, depth: int, logger=None):
    """
    Performs a four-step security analysis pipeline:
    1. Analyze code for vulnerabilities.
    2. Extract keywords and CWE-ID from the result.
    3. Validate the CWE-ID against a local RAG DB and check for similarity.
    4. For validated CWEs, traverse the CWE Knowledge Graph to identify and validate relevant relationships.
    """
    step1_result = None
    step2_result = None
    step3_results = []
    step4_results = [] # To store validated CWE relationships

    # --- [Step 1] First Analysis: Find vulnerabilities ---
    print("\n--- [Step 1] Running initial vulnerability analysis... ---")
    
    class Vulnerability(BaseModel):
        vulnerability: str = Field(description="Description of the vulnerability")
        explanation: str = Field(description="Explanation of why this is a vulnerability")
        fix: str = Field(description="Suggested fix for the vulnerability")

    class Vulnerabilities(BaseModel):
        vulnerabilities: list[Vulnerability] = Field(description="A list of vulnerabilities found in the code")

    first_parser = PydanticOutputParser(pydantic_object=Vulnerabilities)

    try:
        expanded_path = os.path.expanduser(code_file_pattern)
        file_paths = glob.glob(expanded_path)
        if not file_paths:
            print(f"[Error] No files found matching pattern: {code_file_pattern}")
            return
        
        user_code_parts = []
        print("Analyzing the following files:")
        for file_path in file_paths:
            print(f"- {file_path}")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            header = f"--- START OF FILE: {os.path.basename(file_path)} ---\n"
            footer = f"\n--- END OF FILE: {os.path.basename(file_path)} ---"
            user_code_parts.append(f"{header}{content}{footer}")
        user_code = "\n\n".join(user_code_parts)
    except Exception as e:
        print(f"[Error] Failed to read code files: {e}")
        return

    system_prompt = SYSTEM_PROMPTS.get("role_security_analysis")
    first_user_prompt_template = USER_PROMPTS.get("first_request_security_analysis")
    
    first_user_prompt = first_user_prompt_template.format(
        user_code=user_code,
        format_instructions=first_parser.get_format_instructions()
    )

    first_prompt_template = PromptTemplate(
        template="""
{system_prompt}

{user_prompt}
""",
        input_variables=["system_prompt", "user_prompt"],
    )
    
    first_chain = first_prompt_template | llm | first_parser
    
    try:
        step1_result = first_chain.invoke({"system_prompt": system_prompt, "user_prompt": first_user_prompt})
        print("\n--- [Step 1] Analysis Result ---")
        print(json.dumps(step1_result.model_dump(), indent=2, ensure_ascii=False))
    except OutputParserException as e:
        print(f"\n[Parsing Error in Step 1] Failed to parse LLM response: {e}")
        raw_output = str(e.llm_output) if hasattr(e, 'llm_output') else str(e)
        print("\n--- LLM Raw Response ---")
        print(raw_output)
        return

    # --- [Step 2] Second Analysis: Extract keywords and CWE-ID ---
    print("\n--- [Step 2] Extracting keywords and CWE-ID from the analysis result... ---")

    class KeywordResult(BaseModel):
        vulnerability: str = Field(description="Original vulnerability description")
        keywords: list[str] = Field(description="A list of extracted keywords")
        cwe_id: str = Field(description="The most relevant CWE-ID for the vulnerability, e.g., 'CWE-74'")

    class KeywordList(BaseModel):
        vulnerability_keywords: list[KeywordResult] = Field(description="A list of vulnerabilities with their keywords and CWE-IDs")

    second_parser = PydanticOutputParser(pydantic_object=KeywordList)
    
    second_user_prompt_template = USER_PROMPTS.get("second_request_security_analysis")

    second_user_prompt = second_user_prompt_template.format(
        first_analysis_result=json.dumps(step1_result.model_dump(), indent=2),
        format_instructions=second_parser.get_format_instructions()
    )

    second_prompt_template = PromptTemplate(
        template="""
{system_prompt}

{user_prompt}
""",
        input_variables=["system_prompt", "user_prompt"],
    )

    second_chain = second_prompt_template | llm | second_parser

    try:
        step2_result = second_chain.invoke({"system_prompt": system_prompt, "user_prompt": second_user_prompt})
        print("\n--- [Step 2] Keyword Extraction Result ---")
        print(json.dumps(step2_result.model_dump(), indent=2, ensure_ascii=False))
    except OutputParserException as e:
        print(f"\n[Parsing Error in Step 2] Failed to parse LLM response: {e}")
        raw_output = str(e.llm_output) if hasattr(e, 'llm_output') else str(e)
        print("\n--- LLM Raw Response ---")
        print(raw_output)
        return

    # --- [Step 3] Third Analysis: Validate CWE-ID and check similarity ---
    print("\n--- [Step 3] Validating CWE-ID against local RAG DB... ---")

    class CweValidationResult(BaseModel):
        is_similar: bool = Field(description="True if the descriptions refer to the same weakness, False otherwise.")
        reasoning: str = Field(description="A brief justification for the similarity decision.")

    third_parser = PydanticOutputParser(pydantic_object=CweValidationResult)
    third_user_prompt_template = USER_PROMPTS.get("third_request_cwe_validation")

    # --- [Step 4] Pydantic Model Definition for Relationship Analysis ---
    class RelationshipValidationResult(BaseModel):
        is_relationship_valid: bool = Field(description="True if the relationship is logically valid in the context of the original vulnerability.")
        relationship: str = Field(description="A description of the validated relationship, e.g., 'CWE-20 can lead to CWE-502'.")
        justification: str = Field(description="A brief justification for the validation decision.")

    fourth_parser = PydanticOutputParser(pydantic_object=RelationshipValidationResult)
    fourth_user_prompt_template = USER_PROMPTS.get("fifth_request_relationship_analysis")

    for item in step2_result.vulnerability_keywords:
        original_vulnerability_description = item.vulnerability
        initial_cwe_id = item.cwe_id.replace("CWE-", "")
        print(f"\n--- Starting validation and KG traversal for vulnerability: '{original_vulnerability_description}' (starting with CWE-{initial_cwe_id}) ---")
        
        # This vulnerability's specific results will be stored here
        current_vuln_step3_results = []
        current_vuln_step4_results = []

        # --- Knowledge Graph Traversal using Breadth-First Search ---
        cwe_to_process = [(initial_cwe_id, 0)] # (cwe_id, current_depth)
        processed_cwes = set()

        while cwe_to_process:
            source_cwe_id, current_depth = cwe_to_process.pop(0)

            if source_cwe_id in processed_cwes:
                continue
            processed_cwes.add(source_cwe_id)
            
            try:
                # Step 3 is now inside the loop: Validate the current CWE in the traversal
                print(f"\n[Step 3] Validating CWE-{source_cwe_id} at depth {current_depth}...")
                source_cwe_dir = f"data/CWE-{source_cwe_id}"
                if not os.path.isdir(source_cwe_dir):
                    print(f"[Info] Local data for CWE-{source_cwe_id} not found. Running crawler...")
                    subprocess.run(["python3", "crawling_cwe.py", "--cwe-id", source_cwe_id], check=True)

                source_csv_path = os.path.join(source_cwe_dir, f"cwe{source_cwe_id}_cwe_main.csv")
                if not os.path.exists(source_csv_path):
                    print(f"[Error] Main CSV for source CWE-{source_cwe_id} not found.")
                    continue
                
                df_source = pd.read_csv(source_csv_path)
                source_cwe_description = df_source['Description'].iloc[0] if not df_source.empty else "Description not found."

                third_user_prompt = third_user_prompt_template.format(
                    original_vulnerability_description=original_vulnerability_description,
                    cwe_database_description=source_cwe_description,
                    format_instructions=third_parser.get_format_instructions()
                )
                
                third_chain = PromptTemplate(
                    template="""
{system_prompt}

{user_prompt}
""",
                    input_variables=["system_prompt", "user_prompt"],
                ) | llm | third_parser
                step3_single_result = third_chain.invoke({"system_prompt": system_prompt, "user_prompt": third_user_prompt})
                
                print(f"[Result] Similarity Check for CWE-{source_cwe_id}: {step3_single_result.is_similar}")
                current_vuln_step3_results.append({
                    "cwe_id": f"CWE-{source_cwe_id}",
                    "depth": current_depth,
                    "validation_result": step3_single_result.model_dump()
                })

                # If not similar, or max depth reached, stop traversing this path
                if not step3_single_result.is_similar or current_depth >= depth:
                    if current_depth >= depth:
                        print(f"[Info] Reached max depth of {depth}. Stopping traversal from CWE-{source_cwe_id}.")
                    continue

                # Step 4: Find and validate relationships with related CWEs
                print(f"\n[Step 4] Finding and validating relationships for CWE-{source_cwe_id}...")
                related_csv_path = os.path.join(source_cwe_dir, f"cwe{source_cwe_id}_RelatedWeakness.csv")
                if not os.path.exists(related_csv_path):
                    print(f"[Info] No related weaknesses found for CWE-{source_cwe_id}.")
                    continue

                df_related = pd.read_csv(related_csv_path)
                for _, row in df_related.iterrows():
                    target_cwe_id = str(int(row['related_cwe_id']))
                    relationship_type = row['nature']

                    # Get target CWE description
                    target_cwe_dir = f"data/CWE-{target_cwe_id}"
                    if not os.path.isdir(target_cwe_dir):
                        print(f"[Info] Local data for target CWE-{target_cwe_id} not found. Running crawler...")
                        subprocess.run(["python3", "crawling_cwe.py", "--cwe-id", target_cwe_id], check=True)
                    
                    target_csv_path = os.path.join(target_cwe_dir, f"cwe{target_cwe_id}_cwe_main.csv")
                    if not os.path.exists(target_csv_path):
                        print(f"[Error] Main CSV for target CWE-{target_cwe_id} not found.")
                        continue
                        
                    df_target = pd.read_csv(target_csv_path)
                    target_cwe_description = df_target['Description'].iloc[0] if not df_target.empty else "Description not found."
                    
                    # Call LLM to validate the relationship
                    fourth_user_prompt = fourth_user_prompt_template.format(
                        original_vulnerability_description=original_vulnerability_description,
                        source_cwe_description=source_cwe_description,
                        target_cwe_description=target_cwe_description,
                        relationship_type=relationship_type,
                        format_instructions=fourth_parser.get_format_instructions()
                    )

                    fourth_chain = PromptTemplate(
                        template="""
{system_prompt}

{user_prompt}
""",
                        input_variables=["system_prompt", "user_prompt"],
                    ) | llm | fourth_parser
                    step4_single_result = fourth_chain.invoke({"system_prompt": system_prompt, "user_prompt": fourth_user_prompt})
                    
                    print(f"[Result] Relationship Validation: CWE-{source_cwe_id} -> CWE-{target_cwe_id} ({relationship_type}) -> {step4_single_result.is_relationship_valid}")
                    
                    if step4_single_result.is_relationship_valid:
                        current_vuln_step4_results.append(step4_single_result.model_dump())
                        # Add the valid related CWE to the queue for further traversal
                        cwe_to_process.append((target_cwe_id, current_depth + 1))

            except Exception as e:
                print(f"[Error] Failed during pipeline processing for CWE-{source_cwe_id}: {e}")

        # Append results for the current vulnerability to the main lists
        step3_results.extend(current_vuln_step3_results)
        step4_results.extend(current_vuln_step4_results)
        
    # --- Final Logging ---
    request_data = {
        "task": "full_analysis_pipeline",
        "code_file": code_file_pattern,
        "max_depth": depth
    }
    
    # Create a summary of validated relations for the new field
    cwe_relation_summary = [
        res["relationship"] for res in step4_results if res.get("is_relationship_valid")
    ]

    # --- [Step 5] Synthesizing an attack scenario ---
    print("\n--- [Step 5] Synthesizing an attack scenario... ---")
    step5_results = None
    try:
        step5_parser = PydanticOutputParser(pydantic_object=AttackScenarios)
        step5_prompt_template = PromptTemplate(
            template=USER_PROMPTS["fifth_request_attack_scenario"],
            input_variables=["user_code", "step1_analysis_result", "cwe_relation"],
            partial_variables={"format_instructions": step5_parser.get_format_instructions()},
        )
        step5_chain = step5_prompt_template | llm | step5_parser
        step5_response = step5_chain.invoke({
            "user_code": user_code,
            "step1_analysis_result": json.dumps(step1_result.model_dump(), indent=2),
            "cwe_relation": json.dumps(cwe_relation_summary, indent=2)
        })
        step5_results = step5_response.model_dump()
        print("\n--- [Step 5] Attack Scenario Analysis Result ---")
        print(json.dumps(step5_results, indent=2))
    except Exception as e:
        print(f"[Error] Failed during Step 5 (Attack Scenario Analysis): {e}")


    combined_response_data = {
        "step1_vulnerability_analysis": {
            "request_prompt": first_user_prompt,
            "response_data": step1_result.model_dump() if step1_result else None
        },
        "step2_keyword_extraction": {
            "request_prompt": second_user_prompt,
            "response_data": step2_result.model_dump() if step2_result else None
        },
        "step3_cwe_initial_validation": {
            "results": step3_results
        },
        "step4_relationship_analysis": {
            "results": step4_results
        },
        "cwe_relation": cwe_relation_summary,
        "step5_attack_scenario_analysis": {
            "results": step5_results
        }
    }
    log_llm_interaction(model_name, request_data, combined_response_data)


def load_vul4j_source_code(vul4j_id: str) -> str:
    """Reads source code from a Vul4J project ID and returns it as a string."""
    project_base_dir = os.path.expanduser(f'~/vul4j_test/{vul4j_id}/')
    paths_json_path = os.path.join(project_base_dir, 'VUL4J/vulnerable', 'paths.json')
    
    if not os.path.exists(paths_json_path):
        raise FileNotFoundError(f"JSON file not found: {paths_json_path}")

    with open(paths_json_path, 'r', encoding='utf-8') as f:
        paths_data = json.load(f)

    if not paths_data:
        raise ValueError(f"No file information to analyze in {paths_json_path}.")

    user_code_parts = []
    print("Analyzing the following files:")
    for filename, relative_dir in paths_data.items():
        # Correctly combine the directory and filename, assuming paths.json gives the directory
        full_path = os.path.join(project_base_dir, relative_dir)
        print(f"- {os.path.join(relative_dir, filename)}  (Path: {full_path})")
        
        if os.path.exists(full_path):
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            header = f"--- START OF FILE: {os.path.join(relative_dir, filename)} ---\n"
            footer = f"\n--- END OF FILE: {os.path.join(relative_dir, filename)} ---"
            user_code_parts.append(f"{header}{content}{footer}")
        else:
            print(f"  [Warning] File not found, skipping: {full_path}")
    
    user_code = "\n\n".join(user_code_parts)
    if not user_code:
        raise ValueError("Failed to load source code for analysis.")
    
    return user_code

def run_security_analysis_task(llm, model_name, vul4j_id, cwe_id):
    """
    Performs a security analysis task.
    - Reads source code,
    - Finds related CWE information from a CSV,
    - And sends both to an LLM for analysis.
    """
    try:
        # 1. Read source code from the VUL4J project
        user_code = load_vul4j_source_code(vul4j_id)

        # 2. Extract related CWE info from the data/CWE-{cwe_id} directory
        data_dir = f"data/CWE-{cwe_id}"
        if not os.path.isdir(data_dir):
            error_msg = f"Directory '{data_dir}' not found."
            error_msg += f"\nPlease run 'python3 crawling_cwe.py --cwe-id {cwe_id}' first to download the data."
            raise FileNotFoundError(error_msg)

        print(f"\n--- Starting analysis with information from 'CWE-{cwe_id}'. ---")
        
        all_dfs = []
        for filename in os.listdir(data_dir):
            if filename.endswith(".csv"):
                file_path = os.path.join(data_dir, filename)
                try:
                    df = pd.read_csv(file_path, quotechar='"', escapechar='\\', on_bad_lines='skip')
                    all_dfs.append(df)
                except Exception as e:
                    print(f"  [Warning] Error reading file '{file_path}': {e}")

        if not all_dfs:
            cwe_info = f"Could not find a CSV file with CWE information in '{data_dir}'."
            print(f"  [Warning] {cwe_info}")
        else:
            # Combine all dataframes into a single string
            cwe_info_parts = []
            for df in all_dfs:
                cwe_info_parts.append(df.to_string())
            
            cwe_info = "\n\n".join(cwe_info_parts)
            print(f"\n[Reference] CWE information related to 'CWE-{cwe_id}':")
            print(cwe_info)

        # 3. Create and run the LangChain chain
        chain, parser = create_security_chain(llm)
        # Add an output parser to receive the response as a string
        chain = chain | StrOutputParser()
        
        print("\nRequesting security analysis...")
        
        # Get and format the instruction prompt
        instruction_prompt = INSTRUCTION_PROMPTS.get("instruction_security_analysis_with_cwe")
        
        request_data = {
            "task": "security_analysis", "vul4j_id": vul4j_id, "cwe_id": cwe_id,
            "system_prompt_id": "role_security_analysis",
            "system_prompt": SYSTEM_PROMPTS.get("role_security_analysis", "Not Found"),
            "instruction_prompt_id": "instruction_security_analysis_with_cwe",
            "instruction_prompt": instruction_prompt,
            "user_code": user_code,
            "cwe_info": cwe_info,
            "format_instructions": parser.get_format_instructions(),
        }
        
        # Run the chain to get the raw string result
        raw_result = chain.invoke({
            "instruction": instruction_prompt,
            "user_code": user_code,
            "cwe_info": cwe_info,
            "format_instructions": parser.get_format_instructions()
        })

        if not raw_result or not raw_result.strip():
            print("\n[Notice] The LLM did not return an analysis result. No vulnerabilities may have been detected, or the analysis may have failed.")
            return

        # Extract the JSON part from the LLM's response (including markdown code blocks)
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', raw_result, re.DOTALL)
        if not json_match:
            # Also look for a plain JSON object
            json_match = re.search(r'\{.*\}', raw_result, re.DOTALL)

        if json_match:
            json_string = json_match.group(1) if '```json' in json_match.group(0) else json_match.group(0)
            result = json.loads(json_string)
        else:
            # If no JSON is found, trigger a parsing error to log the original output
            raise OutputParserException("Could not find a valid JSON object in the LLM response.", llm_output=raw_result)

        # On success, log the parsed result
        log_llm_interaction(model_name, request_data, result)
        
        print("\n--- Analysis Result ---")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    except OutputParserException as e:
        print(f"\n[Parsing Error] Failed to convert the LLM's response to JSON.")
        raw_output = e.llm_output if hasattr(e, 'llm_output') else str(e)
        # Use a default for request_data as it may not have been defined
        log_llm_interaction(model_name, locals().get('request_data', {}), {"error": "OutputParserException", "raw_output": raw_output})
        
        print("\n--- LLM Raw Response ---")
        print(raw_output)
    
    except (FileNotFoundError, ValueError) as e:
        print(f"[File or Value Error] {e}")
        
    except Exception as e:
        print(f"[Unexpected Error] {e}")

def run_code_analysis_task(llm, model_name, vul4j_id, logger=None):
    """
    Analyzes the overall semantics and functional semantics of source code.
    """
    try:
        # 1. Read source code
        user_code = load_vul4j_source_code(vul4j_id)

        # 2. Analyze the functional semantics of the code
        print("\n[Step 1] Requesting code semantic analysis...")
        
        system_prompt = SYSTEM_PROMPTS.get("role_security_analysis")
        if not system_prompt:
            raise ValueError("Could not find ID 'role_security_analysis' in system_prompts.py.")
        
        instruction_prompt = INSTRUCTION_PROMPTS.get("instruction_code_analysis")
        if not instruction_prompt:
            raise ValueError("Could not find 'instruction_code_analysis' in instruction_prompts.py.")

        prompt = PromptTemplate(
            template="""
{system_prompt}

{user_prompt}
""",
            input_variables=["system_prompt", "user_prompt"],
        )
        
        chain = prompt | llm | StrOutputParser()
        
        if logger:
            logger.info("\n==================== LLM REQUEST ====================")
            logger.info("TASK: Code Semantics Analysis")
            logger.info(f"SYSTEM PROMPT: {system_prompt}")
            logger.info(f"USER PROMPT (Instruction):\n{instruction_prompt.format(user_code='...')}")
            logger.info("=====================================================")

        analysis_result = chain.invoke({"system_prompt": system_prompt, "user_prompt": instruction_prompt})

        if logger:
            logger.info("\n==================== LLM RESPONSE ===================")
            logger.info(analysis_result)
            logger.info("=====================================================")

        log_llm_interaction(model_name, {"task": "code_analysis", "vul4j_id": vul4j_id}, analysis_result)
        print("\n--- Analysis Result ---")
        print(analysis_result)

    except (FileNotFoundError, ValueError) as e:
        print(f"[File or Value Error] {e}")
    except Exception as e:
        print(f"[Unexpected Error] {e}")

def run_security_analysis_for_cwe(llm, model_name, vul4j_id, cwe_id, user_code, logger=None):
    """Helper function to run security analysis for a specific CWE."""
    try:
        # 1. Extract related CWE info from the data/CWE-{cwe_id} directory
        data_dir = f"data/CWE-{cwe_id}"
        cwe_info = ""
        if not os.path.isdir(data_dir):
            error_msg = f"Directory '{data_dir}' not found for CWE-{cwe_id}."
            print(f"  [Warning] {error_msg}")
        else:
            all_dfs = []
            for filename in os.listdir(data_dir):
                if filename.endswith(".csv"):
                    file_path = os.path.join(data_dir, filename)
                    try:
                        df = pd.read_csv(file_path, quotechar='"', escapechar='\\', on_bad_lines='skip')
                        all_dfs.append(df)
                    except Exception as e:
                        print(f"  [Warning] Error reading file '{file_path}': {e}")

            if not all_dfs:
                cwe_info = f"Could not find a CSV file with CWE information in '{data_dir}'."
                print(f"  [Warning] {cwe_info}")
            else:
                cwe_info_parts = [df.to_string() for df in all_dfs]
                cwe_info = "\n\n".join(cwe_info_parts)
                print(f"\n[Reference] Loaded CWE information for 'CWE-{cwe_id}'.")

        # 2. Create and run the LangChain chain
        chain, parser = create_security_chain(llm)
        chain = chain | StrOutputParser()
        
        instruction_prompt = INSTRUCTION_PROMPTS.get("instruction_security_analysis_with_cwe")
        
        request_data = {
            "task": "security_analysis_step3", "vul4j_id": vul4j_id, "cwe_id": cwe_id,
            "system_prompt_id": "role_security_analysis",
            "instruction_prompt_id": "instruction_security_analysis_with_cwe",
        }
        
        if logger:
            final_prompt_for_log = instruction_prompt.format(
                user_code='...too long...',
                cwe_info='...too long...',
                format_instructions=parser.get_format_instructions()
            )
            logger.info("\n==================== LLM REQUEST ====================")
            logger.info(f"TASK: security_analysis (CWE-{cwe_id})")
            logger.info(f"SYSTEM PROMPT: {SYSTEM_PROMPTS.get('role_security_analysis')}")
            logger.info(f"USER PROMPT (Instruction):\n{final_prompt_for_log}")
            logger.info("=====================================================")

        raw_result = chain.invoke({
            "instruction": instruction_prompt,
            "user_code": user_code,
            "cwe_info": cwe_info,
            "format_instructions": parser.get_format_instructions()
        })

        if logger:
            logger.info("\n==================== LLM RESPONSE ===================")
            logger.info(raw_result)
            logger.info("=====================================================")

        if not raw_result or not raw_result.strip():
            print(f"\n[Notice] No analysis result for CWE-{cwe_id}.")
            return None # Return None if analysis fails or no vulnerability is found

        json_match = re.search(r'```json\s*(\{.*?\})\s*```', raw_result, re.DOTALL) or \
                     re.search(r'\{.*\}', raw_result, re.DOTALL)

        if json_match:
            json_string = json_match.group(1) if '```json' in json_match.group(0) else json_match.group(0)
            result = json.loads(json_string)
            log_llm_interaction(model_name, request_data, result)
            print(f"\n--- Analysis Result for CWE-{cwe_id} ---")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return result # Return the result for patch generation
        else:
            raise OutputParserException("Could not find a valid JSON object in the LLM response.", llm_output=raw_result)

    except OutputParserException as e:
        raw_output = e.llm_output if hasattr(e, 'llm_output') else str(e)
        log_llm_interaction(model_name, locals().get('request_data', {}), {"error": "OutputParserException", "raw_output": raw_output})
        print(f"\n[Parsing Error for CWE-{cwe_id}] Failed to convert the LLM's response to JSON.")
        print("\n--- LLM Raw Response ---")
        print(raw_output)
    except Exception as e:
        print(f"[Unexpected Error during CWE-{cwe_id} analysis] {e}")
    return None # Return None if analysis fails or no vulnerability is found


def run_patch_generation_step(llm, model_name, vul4j_id, cwe_id, analysis_result_json, logger=None):
    """Generates a patch based on a security analysis result."""
    print(f"\n--- [Step 4] Generating patch for CWE-{cwe_id} ---")
    try:
        system_prompt = SYSTEM_PROMPTS.get("role_patch_engineer")
        instruction_prompt = INSTRUCTION_PROMPTS.get("patch_generation_instruction")

        prompt = PromptTemplate(
            template="""
{system_prompt}

{user_prompt}
""",
            input_variables=["system_prompt", "user_prompt"],
        )

        chain = prompt | llm | StrOutputParser()
        
        if logger:
            final_prompt_for_log = instruction_prompt.format(
                analysis_result_json=json.dumps(analysis_result_json, indent=2)
            )
            logger.info("\n==================== LLM REQUEST ====================")
            logger.info(f"TASK: patch_generation (CWE-{cwe_id})")
            logger.info(f"SYSTEM PROMPT: {system_prompt}")
            logger.info(f"USER PROMPT (Instruction):\n{final_prompt_for_log}")
            logger.info("=====================================================")

        patch_result_str = chain.invoke({"system_prompt": system_prompt, "user_prompt": instruction_prompt})

        if logger:
            logger.info("\n==================== LLM RESPONSE ===================")
            logger.info(patch_result_str)
            logger.info("=====================================================")

        log_llm_interaction(model_name, {"task": "patch_generation", "vul4j_id": vul4j_id, "cwe_id": cwe_id}, patch_result_str)

        json_match = re.search(r'```json\s*(\{.*?\})\s*```', patch_result_str, re.DOTALL) or \
                     re.search(r'\{.*\}', patch_result_str, re.DOTALL)

        if json_match:
            json_string = json_match.group(1) if '```json' in json_match.group(0) else json_match.group(0)
            result = json.loads(json_string)
            print("\n--- Patch Generation Result ---")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("\n[Warning] Could not parse JSON from patch generation response. Showing raw output:")
            print(patch_result_str)

    except Exception as e:
        print(f"[Unexpected Error during patch generation for CWE-{cwe_id}] {e}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A script for testing LangChain models.")
    parser.add_argument("--model", type=str, required=True, 
                        help="Specify the model to use (e.g., 'ollama:qwen:32b-chat', 'gemini-pro', 'gpt-4o').")
    parser.add_argument("--task", type=str, default=None, choices=["chat", "security_analysis", "batch_chat", "code_analysis", "code_chat", "keyword_analysis"],
                        help="Select the task to perform. If not provided, defaults to the full analysis pipeline (keyword_analysis).")
    parser.add_argument("--system-id", type=str,
                        help="Specify the ID of the system prompt to use for the 'chat' task.")
    parser.add_argument("--user-id", type=str,
                        help="Specify the ID of the user prompt to use for the 'chat' task.")
    parser.add_argument("--code-file", type=str,
                        help="Specify the path to the code file for the 'code_chat' task.")
    parser.add_argument("--vul4j_id", type=str,
                        help="Specify the Vul4J ID to use for 'security_analysis' or 'code_analysis' tasks.")
    parser.add_argument("--cwe-id", type=str,
                        help="Specify the CWE ID to reference for the 'security_analysis' task (e.g., '20').")
    parser.add_argument("--generate-patch", action="store_true",
                        help="If specified with 'security_analysis', generate a patch if a vulnerability is found.")
    parser.add_argument("--depth", type=int, default=2,
                        help="Set the maximum traversal depth for KG relationship analysis in Step 4.")
    parser.add_argument("--debug", action="store_true", 
                        help="Enable debug mode for verbose logging of requests and responses.")
    args = parser.parse_args()

    # Verify required arguments for each task
    if args.task == 'chat' and (not args.system_id or not args.user_id):
        parser.error("--system-id and --user-id are required for the 'chat' task.")
    # If no task is specified, it defaults to keyword_analysis, which requires a code file.
    if (args.task is None or args.task in ['code_chat', 'keyword_analysis']) and not args.code_file:
        parser.error("--code-file is required for the default analysis pipeline and for 'code_chat' or 'keyword_analysis' tasks.")
    if args.task == 'security_analysis' and (not args.vul4j_id or not args.cwe_id):
        parser.error("--vul4j_id and --cwe_id are required for the 'security_analysis' task.")
    if args.task == 'code_analysis' and not args.vul4j_id:
        parser.error("--vul4j_id is required for the 'code_analysis' task.")

    logger = None
    if args.debug:
        logger = setup_debug_logger(args.model)
        logger.info(f"--- Debug Mode Enabled: Logging to console and file ---")

    try:
        # Load API keys
        api_keys = load_api_keys()
        
        # Get the LLM instance
        print(f"Loading model '{args.model}'...")
        llm = get_llm(args.model, api_keys)
        print("Model loaded successfully.\n")
        
        # Determine the task to run
        task_to_run = args.task
        if task_to_run is None:
            task_to_run = "keyword_analysis" # Default task

        if task_to_run == "chat":
            run_chat_task(llm, args.model, args.system_id, args.user_id, logger=logger)
        elif task_to_run == "code_chat":
            # Set default prompts for code_chat if not provided
            system_id = args.system_id if args.system_id else "role_security_analysis"
            user_id = args.user_id if args.user_id else "first_request_security_analysis"
            run_code_chat_task(llm, args.model, args.code_file, system_id, user_id, logger=logger)
        elif task_to_run == "keyword_analysis":
            run_full_analysis_pipeline(llm, args.model, args.code_file, args.depth, logger=logger)
        elif task_to_run == "security_analysis":
            user_code = load_vul4j_source_code(args.vul4j_id)
            
            # Find related CWEs from the CSV file
            base_cwe_id = args.cwe_id
            related_cwe_path = os.path.join(f"data/CWE-{base_cwe_id}", f"cwe{base_cwe_id}_RelatedWeakness.csv")
            
            cwe_to_analyze = {base_cwe_id} # Use a set to avoid duplicates

            if os.path.exists(related_cwe_path):
                print(f"\nFound RelatedWeakness file: {related_cwe_path}")
                try:
                    df = pd.read_csv(related_cwe_path)
                    if 'related_cwe_id' in df.columns:
                        related_ids = df['related_cwe_id'].dropna().astype(int).astype(str).tolist()
                        cwe_to_analyze.update(related_ids)
                        print(f"Found {len(related_ids)} related CWEs. Total to analyze: {len(cwe_to_analyze)}")
                except Exception as e:
                    print(f"[Warning] Could not read or parse related CWEs from {related_cwe_path}: {e}")
            else:
                print(f"[Info] No RelatedWeakness.csv found for CWE-{base_cwe_id}. Analyzing the base CWE only.")

            # Run analysis for the base CWE and all related CWEs
            for cwe_id in sorted(list(cwe_to_analyze), key=int):
                 print(f"\n\n--- Running security analysis for CWE-{cwe_id} ---")
                 analysis_result = run_security_analysis_for_cwe(llm, args.model, args.vul4j_id, cwe_id, user_code, logger=logger)
                 if args.generate_patch and analysis_result and analysis_result.get("is_vulnerable"):
                     run_patch_generation_step(llm, args.model, args.vul4j_id, cwe_id, analysis_result, logger=logger)

        elif task_to_run == "batch_chat":
            run_batch_chat_task(llm, args.model, logger=logger)
        elif task_to_run == "code_analysis":
            run_code_analysis_task(llm, args.model, args.vul4j_id, logger=logger)
            
    except (ValueError, FileNotFoundError) as e:
        print(f"[Error] {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main() 