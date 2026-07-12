FROM python:3.12-slim

LABEL description="LLM Shield proxy - intercepts and masks AI provider API calls"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TRANSFORMERS_NO_ADVISORY_WARNINGS=1
ENV HF_HUB_NO_ADVISORY_WARNINGS=1
ENV HF_HUB_DISABLE_TELEMETRY=1
ENV TOKENIZERS_PARALLELISM=false

WORKDIR /addon

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu

COPY proxy_addon.py .
COPY semantic_masking.py .
COPY semantic_obfuscation.py .
COPY shield_config.json .

RUN mkdir -p /addon/.agent

ENV MASKING_STRATEGY=token_substitution
ENV SEMANTIC_OBFUSCATION=true
ENV SEMANTIC_OBFUSCATION_LEVEL=standard
ENV SEMANTIC_OBFUSCATION_DECODE_RESPONSE=true
ENV SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM=false
ENV SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY=false

EXPOSE 8923

CMD ["mitmdump", \
     "-s", "/addon/proxy_addon.py", \
     "--mode", "regular", \
     "--listen-port", "8923", \
     "--set", "connection_strategy=lazy", \
     "--set", "upstream_cert=true"]
