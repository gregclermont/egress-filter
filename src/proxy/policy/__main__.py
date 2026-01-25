"""Allow running the policy module directly: python -m proxy.policy <workflow.yml>"""

from .cli import main

if __name__ == "__main__":
    main()
