
""" this module contains all foreground and backgreound colors for use in the terminal
"""

# Step 0.2: Define fColors class contains all Foreground colors byte chars
class fColors:
    # Standard Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Light (Bright) Colors
    LIGHT_BLACK = '\033[90m'
    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\033[92m'
    LIGHT_YELLOW = '\033[93m'
    LIGHT_BLUE = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'
    LIGHT_CYAN = '\033[96m'
    LIGHT_WHITE = '\033[97m'

    # Reset
    RESET = '\033[0m'


# Step 0.3: Define bColors class contains all Background colors byte chars
class bColors:
    # Background Colors
    BLACK = '\033[40m'
    RED = '\033[41m'
    GREEN = '\033[42m'
    YELLOW = '\033[43m'
    BLUE = '\033[44m'
    MAGENTA = '\033[45m'
    CYAN = '\033[46m'
    WHITE = '\033[47m'

    # Light (Bright) Background Colors
    LIGHT_BLACK = '\033[100m'
    LIGHT_RED = '\033[101m'
    LIGHT_GREEN = '\033[102m'
    LIGHT_YELLOW = '\033[103m'
    LIGHT_BLUE = '\033[104m'
    LIGHT_MAGENTA = '\033[105m'
    LIGHT_CYAN = '\033[106m'
    LIGHT_WHITE = '\033[107m'

    # Reset
    RESET = '\033[0m'


