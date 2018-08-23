# Why would you change me?
SITE_NAME = "Moffle"

# A path, like "/var/lib/znc/users/"
LOG_BASE = "/var/lib/znc/users/logger/"

# If you have an abnormal ZNC logging setup, implement your own LogPath thingy
# and set this to your implementation class name.
# Most people will not worry about this.
LOG_PATH_CLASS = "LogPath"

# Whether or not Flask is behind a HTTP proxy.
# Affects whether or not we insert proxy middleware.
FLASK_PROXY = True

# Flask secret key for session support.
SECRET_KEY = "your secret key"

# For OAuth support.
GOOGLE_OAUTH_CONSUMER_KEY = ""
GOOGLE_OAUTH_CONSUMER_SECRET = ""

# Number of search worker processes.
SEARCH_WORKERS = 8

# Number of context lines around each search result.
SEARCH_CONTEXT = 4

# The number of weeks to segment AJAX searches into.
SEARCH_CHUNK_INTERVAL_WEEKS = 4

# Whether to enable AJAX search.
SEARCH_AJAX_ENABLED = True

# The order in which to prefer languages to send to clients
# (with respect to their Accept-Language header)
LOCALE_PREFER = ['ja', 'en']

# Debug options you shouldn't touch
DEBUG_PROFILER = False

# 4-tuples of allow/deny, oauth email (* = all), scope (network/channel/*),
# match (regex or *)
# Rules are considered by their scope, then their action
# Network scope allow/deny must be explicitly stated as channel-scope rules
# have no consideration of their containing network
ACL = (
    # Public ACL rules
    ('deny', '*', ('*', '*'), ('root', 'root')),
    ('allow', '*', ('network', 'ocf'), ('root', 'root')),
    ('allow', '*', ('channel', '#rebuild'), ('network', 'ocf')),
    ('allow', '*', ('network', 'rizon'), ('root', 'root')),
    ('allow', '*', ('channel', '#help'), ('network', 'rizon')),
)

DEBUG_PYINSTRUMENT = False

GREP_BUILDER_CLASS = 'GrepBuilder'
