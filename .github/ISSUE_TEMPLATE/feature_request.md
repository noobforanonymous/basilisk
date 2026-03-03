---
name: Feature request
about: Suggest a new feature for Basilisk
title: ''
labels: enhancement
assignees: ''

---

title: "[FEATURE] "
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for suggesting a feature!
  
  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: What problem does this solve?
      placeholder: I'm frustrated when...
    validations:
      required: true
  
  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: How should this work?
      placeholder: I'd like to see...
    validations:
      required: true
  
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered
      description: What other solutions did you consider?
  
  - type: textarea
    id: examples
    attributes:
      label: Examples
      description: Show examples of how this would work
      render: shell
  
  - type: checkboxes
    id: contribution
    attributes:
      label: Contribution
      options:
        - label: I'm willing to implement this feature
