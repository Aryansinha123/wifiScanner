import logging
import sys
import tkinter as tk

from gui.main_window import MainWindow


def setup_logging():
    """
    Configures application-wide logging.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def main():
    setup_logging()
    logger = logging.getLogger("Wi-Fi Network Security Scanner")
    logger.info("Starting Wi-Fi Network Security Scanner Phase 1...")

    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()