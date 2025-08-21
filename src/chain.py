from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field
from typing import List

from prompts.system_prompts import SYSTEM_PROMPTS

class SecurityReport(BaseModel):
    most_relevant_cwe: str = Field(description="The single most relevant CWE type identified from the provided list (e.g., 'CWE-707').")
    analysis_result: str = Field(description="Detailed security analysis of the user's code, explaining the vulnerability in relation to the identified CWE type.")
    vulnerable_code_lines: List[str] = Field(description="A list of specific line numbers or code snippets that are vulnerable.")
    recommendation: str = Field(description="Recommendations to fix the vulnerability and improve security.")

def create_security_chain(llm):
    """보안 분석을 위한 LangChain 체인을 생성합니다."""
    # JSON 출력 파서는 여기서 사용하지 않고, 응답을 받은 후 수동으로 파싱합니다.
    parser = JsonOutputParser(pydantic_object=SecurityReport)

    # 시스템 프롬프트, 지침, 사용자 입력을 포함하는 프롬프트 템플릿 생성
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPTS["role_security_analysis"] + "\n{format_instructions}"),
        ("human", 
         "{instruction}\n\n"
         "--- Source Code to Analyze ---\n"
         "{user_code}\n\n"
         "--- Related CWE Information ---\n"
         "{cwe_info}"
        ),
    ])

    # 파서를 제외하고 체인 구성 및 반환
    chain = prompt | llm
    return chain, parser 