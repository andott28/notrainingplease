import os
import sys


def main() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, root)
    from gui import App

    App().run()


if __name__ == "__main__":
    main()
