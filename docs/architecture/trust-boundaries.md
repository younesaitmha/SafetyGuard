# Trust boundaries

## Why trust boundaries matter

LLM systems often fail when all content is treated as equally trustworthy. This gateway uses explicit trust segmentation to reduce the chance that untrusted content can override trusted instructions.

## Trust levels

### Trusted

Sources controlled by the gateway or platform:

- gateway-generated system policy
- gateway-generated developer/task framing
- internal enforcement metadata

### Semi-trusted

Sources that may be useful but should not override trusted instructions:

- retrieved internal knowledge
- previous assistant outputs
- tool results from internal systems

### Untrusted

Sources that must never be treated as authoritative:

- user input
- user attachments
- web/browser content
- any content claiming authority without verification

## Trust application in prompt building

Prompt sections are built explicitly by trust level:

- trusted policy and task sections first
- semi-trusted context next
- untrusted user content last

This is intended to reduce:

- prompt injection impact
- authority confusion
- hidden instruction override behavior

## Trust-related implementation rules

- untrusted input must not be merged into trusted sections
- tool outputs should not automatically become trusted
- retrieved content remains semi-trusted even if internal
- user-supplied privileged roles should not be implicitly trusted
- output should be scanned before returning, regardless of internal origin

## Common failure modes to avoid

- putting raw user text into system prompt sections
- allowing browser results to be treated as trusted instructions
- granting tools based solely on model suggestion
- echoing retrieved confidential content without output checks
