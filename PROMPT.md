ROLE: Senior Systems Integration Engineer.

CONTEXT:
We are building a highly constrained, asynchronous, multi-container mix-network. The workload is strictly divided among three developers to avoid merge conflicts.
I am providing two files:

1. `code.md` (the legacy v1 codebase for context).
2. `plan_[INSERT_YOUR_DOMAIN].md` (the strict architectural specification for MY specific domain).

PRIME DIRECTIVE:
Your task is to generate the production-ready code ONLY for the files and features outlined in my specific `plan_*.md` file.

STRICT BOUNDARY RULES:

1. NO SCOPE CREEP: Do not invent features, modify architectural rules, or write code meant for other domains.
2. RESPECT THE CONTRACTS: If my domain needs to interact with another team member's domain (e.g., calling crypto functions from the UI, or passing bytearrays to the network loop), you MUST use mocked function calls or the exact black-box interfaces defined in my plan. Do NOT attempt to implement their underlying logic.
3. EXACT COMPLIANCE: Follow the byte-math, threading constraints (The Two-World Rule), and network protocols exactly as written in the plan. Zero deviations allowed.

OUTPUT FORMAT:
Output the complete code for my assigned files sequentially.
Enclose each in a standard markdown code block with the exact filename commented at the top (e.g., `# src/filename.py`).
If you hit a token output limit, stop at a clean file break and wait for me to say "continue".

Read the provided plan carefully. Acknowledge these strict boundaries, and begin generating the codebase for my domain.
