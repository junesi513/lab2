# LLM-GOT (Generative Offensive-security Test)

## 1. 프로젝트 개요

LLM-GOT는 다양한 LLM(Large Language Model)을 활용하여 보안 취약점을 분석하고, 일반적인 채팅 기능을 테스트하기 위한 프레임워크입니다. 사용자는 간단한 명령줄 인터페이스(CLI)를 통해 원하는 LLM 모델과 작업을 선택하여 실행할 수 있습니다.

### 주요 기능

-   **다중 LLM 지원**: `Ollama`, `Gemini`, `GPT` 등 다양한 모델을 지원하며, 쉽게 확장할 수 있습니다.
-   **작업 분리**: 일반 채팅(`chat`), 모든 프롬프트 조합 테스트(`batch_chat`), 보안 분석(`security_analysis`) 등 명확하게 구분된 작업을 제공합니다.
-   **프롬프트 관리**: `system`, `user`, `instruction` 등 역할별로 프롬프트를 분리하여 관리의 용이성과 재사용성을 높였습니다.
-   **보안 분석 자동화**: `Vul4J` 데이터셋과 연동하여 지정된 소스 코드의 보안 취약점을 자동으로 분석하고 결과를 JSON 형식으로 제공합니다.
-   **상세 로깅**: 모든 LLM 상호작용(요청, 응답)을 모델 및 날짜별로 구조화된 JSON 파일로 기록하여 분석과 디버깅을 용이하게 합니다.

## 2. 실행 방법

### 2.1. 사전 준비

1.  **Python 설치**: Python 3.10 이상이 필요합니다.
2.  **의존성 설치**: 프로젝트 루트 디렉터리에서 다음 명령을 실행하여 필요한 라이브러리를 설치합니다.
    ```bash
    pip install -r requirements.txt
    ```
3.  **API 키 설정**:
    -   `config.json` 파일을 생성하고 `OPENAI_API_KEY`와 `GEMINI_API_KEY`를 추가합니다.
        ```json
        {
          "OPENAI_API_KEY": "YOUR_OPENAI_API_KEY",
          "GEMINI_API_KEY": "YOUR_GEMINI_API_KEY"
        }
        ```
    -   또는 `.env` 파일을 생성하거나 환경 변수를 통해 API 키를 설정할 수 있습니다.

### 2.2. 실행 명령어

스크립트는 `start.py`를 통해 실행되며, `--model`과 `--task` 인자를 필수로 지정해야 합니다.

-   `--model`: 사용할 LLM 모델을 지정합니다. (예: `ollama:qwen:32b-chat`, `gemini-pro`, `gpt-4o`)
-   `--task`: 수행할 작업을 선택합니다. (`chat`, `batch_chat`, `security_analysis`)

#### 1. 일반 채팅 (chat)

-   지정된 시스템 및 유저 프롬프트로 LLM과 상호작용합니다.
-   `--system-id`와 `--user-id`를 필수로 지정해야 합니다.
-   **사용 예시**:
    ```bash
    python start.py --model "ollama:qwen:32b-chat" --task chat --system-id role_developer --user-id task_create_function
    ```
    ```bash
    python start.py --model "ollama:qwen3:32b" --task security_analysis --vul4j_id "VUL4J-1" --cwe-id "20"
    ```
    ```bash
    python start.py --model "ollama:gpt-oss:20b" --task chat --system-id role_developer --user-id question_hello
    ```

#### 2. 배치 채팅 (batch_chat)

-   `prompts` 디렉터리에 정의된 모든 시스템/유저 프롬프트 조합을 실행하여 결과를 확인합니다.
-   **사용 예시**:
    ```bash
    python start.py --model "gemini-pro" --task batch_chat
    ```

#### 3. 보안 분석 (security_analysis)

-   `Vul4J` 프로젝트의 소스 코드를 분석하여 보안 취약점을 식별합니다.
-   `--vul4j_id`를 통해 분석할 프로젝트를 지정합니다.
-   **사용 예시**:
    ```bash
    python start.py --model "gpt-4o" --task security_analysis --vul4j_id "VUL4J-1"
    ```

## 3. Code Flow

1.  **초기화 (`main` 함수)**
    1.  `argparse`를 사용하여 커맨드 라인 인자(`model`, `task`, `system-id` 등)를 파싱합니다.
    2.  `load_api_keys()`를 호출하여 `config.json` 또는 환경 변수에서 API 키를 로드합니다.
    3.  `get_llm()`을 호출하여 `--model` 인자에 맞는 LangChain LLM 인스턴스를 생성합니다. (`Ollama`, `Gemini`, `GPT` 중 선택)

2.  **작업 분기 (`main` 함수)**
    -   `--task` 인자의 값에 따라 다음 작업 중 하나를 수행합니다.

    -   **`chat` 작업 (`run_chat_task`)**:
        1.  `--system-id`와 `--user-id`에 해당하는 프롬프트를 `SYSTEM_PROMPTS`와 `USER_PROMPTS`에서 조회합니다.
        2.  `ChatPromptTemplate`을 사용하여 시스템 및 유저 프롬프트를 조합합니다.
        3.  생성된 프롬프트와 LLM을 연결하여 체인(`chain`)을 구성하고, `invoke`를 통해 실행합니다.
        4.  결과를 콘솔에 출력하고 `log_llm_interaction`을 호출하여 상호작용을 로깅합니다.

    -   **`batch_chat` 작업 (`run_batch_chat_task`)**:
        1.  `SYSTEM_PROMPTS`와 `USER_PROMPTS`에 정의된 모든 프롬프트 조합에 대해 반복문을 실행합니다.
        2.  각 조합에 대해 `chat` 작업과 동일한 방식으로 체인을 생성하고 실행합니다.
        3.  각각의 결과를 콘솔에 출력하고 로깅합니다.

    -   **`security_analysis` 작업 (`run_security_analysis_task`)**:
        1.  `--vul4j_id`를 기반으로 분석할 소스 코드의 경로(`~/vul4j_test/{vul4j_id}`)를 설정합니다.
        2.  `paths.json` 파일을 읽어 분석 대상 파일 목록을 가져옵니다.
        3.  각 파일의 내용을 읽어 하나의 문자열(`user_code`)로 병합합니다.
        4.  `create_security_chain`을 호출하여 보안 분석용 LangChain 체인과 출력 파서(`parser`)를 생성합니다.
        5.  체인을 실행하여 `user_code`에 대한 보안 분석을 요청합니다.
        6.  결과를 JSON 형식으로 파싱하고 콘솔에 출력합니다. `OutputParserException` 발생 시 원본 응답을 로깅합니다.
        7.  `log_llm_interaction`을 호출하여 분석 요청 및 결과를 로깅합니다.

3.  **로깅 (`log_llm_interaction`)**
    1.  LLM과의 모든 상호작용은 이 함수를 통해 기록됩니다.
    2.  `logs/{모델명}/{날짜}/{타임스탬프}.json` 경로에 요청 및 응답 데이터를 JSON 파일로 저장합니다.
    3.  이를 통해 모든 테스트 결과를 체계적으로 추적하고 관리할 수 있습니다.

## 4. 디렉터리 구조

```
/
├── logs/                 # LLM 상호작용 로그
├── prompts/              # 프롬프트 모음
│   ├── system_prompts.py
│   ├── user_prompts.py
│   └── instruction_prompts.py
├── src/                  # 핵심 로직 (체인 생성 등)
│   └── chain.py
├── start.py              # 메인 실행 스크립트
├── requirements.txt      # 의존성 목록
├── config.json           # (선택) API 키 설정
└── README.md             # 프로젝트 설명
``` # lab2
