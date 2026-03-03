---
name: Bug report
about: " Report a bug in Basilisk"
title: ''
labels: bug
assignees: ''

---

title: "[BUG] "
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for reporting a bug! Please fill out the information below.
  
  - type: input
    id: version
    attributes:
      label: Basilisk Version
      description: Which version are you using?
      placeholder: "0.1.x"
    validations:
      required: true
  
  - type: textarea
    id: description
    attributes:
      label: Bug Description
      description: A clear description of the bug
      placeholder: What happened?
    validations:
      required: true
  
  - type: textarea
    id: steps
    attributes:
      label: Steps to Reproduce
      description: How can we reproduce this?
      placeholder: |
        1. Run command...
        2. Configure...
        3. See error...
    validations:
      required: true
  
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What should happen?
    validations:
      required: true
  
  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: What actually happened?
    validations:
      required: true
  
  - type: textarea
    id: logs
    attributes:
      label: Logs/Screenshots
      description: Paste any relevant logs or screenshots
      render: shell
  
  - type: dropdown
    id: os
    attributes:
      label: Operating System
      options:
        - Linux
        - macOS
        - Windows
        - Docker
    validations:
      required: true
  
  - type: input
    id: python
    attributes:
      label: Python Version
      placeholder: "3.11"
