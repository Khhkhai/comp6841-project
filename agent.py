from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

from tools import send_email

SYSTEM_PROMPT = (
    "You are a helpful assistant that accept document as prompt and send email  "
    "user's behalf. Use send_email tool to send email. Complete the user's request."
)

def build_agent(model: str = "llama3.1:8b", temperature: float = 0.0, tools=None):
    llm = ChatOllama(model=model, temperature=temperature)
    return create_react_agent(llm, tools=tools if tools is not None else [send_email])
