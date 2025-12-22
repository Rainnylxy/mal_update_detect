
""" this module contains all styles for texts in the terminal
"""

# Step 0.4: Define stringFormat class contains all text formatting byte chars
class stringFormat:
    # Text Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'    # May not work on all terminals
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    INVERT = '\033[7m'
    HIDDEN = '\033[8m'
    STRIKETHROUGH = '\033[9m'  # May not work on all terminals

    # Reset Formatting
    RESET = '\033[0m'
    RESET_BOLD = '\033[21m'
    RESET_DIM = '\033[22m'
    RESET_UNDERLINE = '\033[24m'
    RESET_BLINK = '\033[25m'
    RESET_INVERT = '\033[27m'
    RESET_HIDDEN = '\033[28m'
    RESET_STRIKETHROUGH = '\033[29m'
