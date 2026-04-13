---
name: Feature request
about: Suggest a new tool or improvement to apksaw
title: "[Feature] "
labels: enhancement
assignees: ''
---

## Problem / motivation

Describe the problem you are trying to solve or the gap in apksaw's current capabilities.

Example: "When analysing obfuscated APKs, there is no way to automatically rename methods based on string references."

## Proposed solution

A clear description of what you would like to see added or changed. If you have a specific API in mind, describe the tool name, its parameters, and the expected output shape.

```python
# Example proposed tool signature
def rename_methods_from_strings(session_id: str, confidence: float = 0.8) -> dict:
    ...
```

## Alternatives considered

Any alternative approaches you have evaluated and why you prefer the proposed solution.

## Additional context

Screenshots, references to research papers, links to similar tools, or any other context that supports the request.
