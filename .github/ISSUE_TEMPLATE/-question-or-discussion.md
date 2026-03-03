---
name: " Question or Discussion"
about: Ask a question or start a discussion
title: ''
labels: ''
assignees: ''

---

title: "[QUESTION] "
labels: ["question"]
body:
  - type: markdown
    attributes:
      value: |
        Have a question about Basilisk? Let's discuss!
  
  - type: textarea
    id: question
    attributes:
      label: Your Question
      description: What would you like to know?
    validations:
      required: true
  
  - type: textarea
    id: context
    attributes:
      label: Context
      description: Any additional context?
  
  - type: input
    id: version
    attributes:
      label: Basilisk Version
      placeholder: "0.1.x"
