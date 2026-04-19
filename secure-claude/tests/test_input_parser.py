from secure_claude import input_parser


def test_parse_pre_tool_use_standard():
    payload = {"tool_name": "Bash", "cwd": "/x", "tool_input": {"command": "ls"}}
    r = input_parser.parse_tool_event(payload)
    assert r.tool_name == "Bash"
    assert r.cwd == "/x"
    assert r.tool_input == {"command": "ls"}


def test_parse_tool_input_as_string_json():
    payload = {"tool_name": "Bash", "cwd": "/x", "tool_input": '{"command":"ls"}'}
    r = input_parser.parse_tool_event(payload)
    assert r.tool_input == {"command": "ls"}


def test_parse_tool_input_malformed_string_becomes_empty():
    payload = {"tool_name": "Bash", "cwd": "/x", "tool_input": "{malformed"}
    r = input_parser.parse_tool_event(payload)
    assert r.tool_input == {}


def test_parse_tool_input_non_object_becomes_empty():
    payload = {"tool_name": "Bash", "cwd": "/x", "tool_input": ["a", "b"]}
    r = input_parser.parse_tool_event(payload)
    assert r.tool_input == {}


def test_missing_tool_name_defaults_unknown():
    r = input_parser.parse_tool_event({})
    assert r.tool_name == "unknown"
    assert r.tool_input == {}
    assert r.cwd == ""


def test_extract_post_tool_text_bash_stdout():
    payload = {"tool_name": "Bash", "tool_response": {"stdout": "hi", "stderr": ""}}
    assert input_parser.extract_post_tool_text(payload) == "hi"


def test_extract_post_tool_text_string_response():
    payload = {"tool_name": "Read", "tool_response": "file contents"}
    assert input_parser.extract_post_tool_text(payload) == "file contents"


def test_extract_post_tool_text_nested_text_key():
    payload = {"tool_name": "WebFetch", "tool_response": {"text": "fetched"}}
    assert input_parser.extract_post_tool_text(payload) == "fetched"


def test_extract_post_tool_text_text_result_for_llm():
    payload = {"tool_name": "X", "tool_response": {"textResultForLlm": "llm text"}}
    assert input_parser.extract_post_tool_text(payload) == "llm text"


def test_extract_post_tool_text_falls_back_to_tool_output():
    payload = {"tool_name": "X", "tool_output": {"stdout": "via output"}}
    assert input_parser.extract_post_tool_text(payload) == "via output"


def test_extract_post_tool_text_missing_returns_empty():
    assert input_parser.extract_post_tool_text({"tool_name": "X"}) == ""


def test_extract_post_tool_text_dict_without_known_key_returns_json():
    payload = {"tool_name": "X", "tool_response": {"weird_key": "weird_val"}}
    result = input_parser.extract_post_tool_text(payload)
    assert "weird_val" in result  # falls back to JSON string representation


def test_extract_user_prompt_prompt_key():
    assert input_parser.extract_user_prompt({"prompt": "hello"}) == "hello"


def test_extract_user_prompt_raw_fallback():
    assert input_parser.extract_user_prompt({"_raw": "raw text"}) == "raw text"


def test_extract_user_prompt_empty():
    assert input_parser.extract_user_prompt({}) == ""
