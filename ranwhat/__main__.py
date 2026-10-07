"""Allow `python -m ranwhat` as well as the installed `ranwhat` script."""
import sys

if __name__ == "__main__":
    # The hook runs before every tool call Claude Code makes, so it skips
    # the rest of the command line's imports: it needs only watch's rules.
    if sys.argv[1:3] == ["hook", "run"]:
        from .hook import main as hook_main
        sys.exit(hook_main(sys.argv[3:]))
    from .cli import main
    sys.exit(main())
