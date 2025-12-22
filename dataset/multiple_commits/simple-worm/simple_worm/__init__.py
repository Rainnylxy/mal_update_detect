import warnings

from fenics import *
from ffc.quadrature.deprecation import QuadratureRepresentationDeprecationWarning

set_log_level(100)
warnings.simplefilter('ignore', QuadratureRepresentationDeprecationWarning)
