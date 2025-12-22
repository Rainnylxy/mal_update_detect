from abc import ABC
from typing import Tuple

import numpy as np
from fenics import *

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass

MP_KEYS = ['K', 'K_rot', 'A', 'B', 'C', 'D']

MP_DEFAULT_K = 10.
MP_DEFAULT_K_ROT = 1.
MP_DEFAULT_A = 1.
MP_DEFAULT_B = 0.
MP_DEFAULT_C = 1.
MP_DEFAULT_D = 0.

GT = '>'
GTE = '>='
LT = '<'
LTE = '<='

# These bounds do not reflect physical (real-world) constraints but are necessary for the
# inverse optimisation to run properly. Without bounds the optimisation fails to converge.
MP_BOUNDS = {
    'K': {
        'LB_TYPE': GTE,
        'LB': 1.,
        'UB_TYPE': LTE,
        'UB': 1000.,
    },
    'K_rot': {
        'LB_TYPE': GT,
        'LB': 0.,
        'UB_TYPE': LTE,
        'UB': 100.,
    },
    'A': {
        'LB_TYPE': GT,
        'LB': 0.,
        'UB_TYPE': LTE,
        'UB': 100.,
    },
    'B': {
        'LB_TYPE': GTE,
        'LB': 0.,
        'UB_TYPE': LTE,
        'UB': 10.,
    },
    'C': {
        'LB_TYPE': GT,
        'LB': 0.,
        'UB_TYPE': LTE,
        'UB': 100.,
    },
    'D': {
        'LB_TYPE': GTE,
        'LB': 0.,
        'UB_TYPE': LTE,
        'UB': 10.,
    },
}


class MaterialParameters(ABC):
    """
    Material parameters.
    """

    def __init__(
            self,
            K: float = MP_DEFAULT_K,
            K_rot: float = MP_DEFAULT_K_ROT,
            A: float = MP_DEFAULT_A,
            B: float = MP_DEFAULT_B,
            C: float = MP_DEFAULT_C,
            D: float = MP_DEFAULT_B,
    ):
        """
        K: The external force exerted on the worm by the fluid.
        K_rot: The external moment.
        A: The bending modulus.
        B: The bending viscosity.
        C: The twisting modulus.
        D: The twisting viscosity.
        """
        self.K = K
        self.K_rot = K_rot
        self.A = A
        self.B = B
        self.C = C
        self.D = D
        self._validate()

    def _validate(self):
        """
        Check bounds.
        """
        for k in MP_KEYS:
            v = float(getattr(self, k))
            bounds = MP_BOUNDS[k]
            if bounds['LB_TYPE'] == GT:
                assert v > bounds['LB'], f'{k} must be > {bounds["LB"]}'
            elif bounds['LB_TYPE'] == GTE:
                assert v >= bounds['LB'], f'{k} must be >= {bounds["LB"]}'
            if bounds['UB_TYPE'] == LT:
                assert v < bounds['UB'], f'{k} must be < {bounds["UB"]}'
            elif bounds['UB_TYPE'] == LTE:
                assert v <= bounds['UB'], f'{k} must be <= {bounds["UB"]}'

    def to_fenics(self) -> 'MaterialParametersFenics':
        """Convert to Fenics-compatible instance."""
        args = {k: getattr(self, k) for k in MP_KEYS}
        return MaterialParametersFenics(**args)

    @staticmethod
    def get_bounds(eps: float = 1e-5) -> Tuple[np.ndarray, np.ndarray]:
        """
        Convert the bounds to two lists, one for the lower, another for upper bounds.
        """
        lbs = []
        ubs = []

        for k in MP_KEYS:
            bounds = MP_BOUNDS[k]

            lb = bounds['LB']
            if bounds['LB_TYPE'] == GT:
                lb = bounds['LB'] + eps
            lbs.append(lb)
            
            ub = bounds['UB']
            if bounds['UB_TYPE'] == LT:
                ub = bounds['UB'] - eps
            ubs.append(ub)

        return [
            np.array(lbs),
            np.array(ubs)
        ]


class MaterialParametersFenics(MaterialParameters):
    def __init__(
            self,
            K: Constant = Constant(MP_DEFAULT_K),
            K_rot: Constant = Constant(MP_DEFAULT_K_ROT),
            A: Constant = Constant(MP_DEFAULT_A),
            B: Constant = Constant(MP_DEFAULT_B),
            C: Constant = Constant(MP_DEFAULT_C),
            D: Constant = Constant(MP_DEFAULT_D),
    ):
        # Ensure values are fenics constants
        if not isinstance(K, Constant):
            K = Constant(K)
        if not isinstance(K_rot, Constant):
            K_rot = Constant(K_rot)
        if not isinstance(A, Constant):
            A = Constant(A)
        if not isinstance(B, Constant):
            B = Constant(B)
        if not isinstance(C, Constant):
            C = Constant(C)
        if not isinstance(D, Constant):
            D = Constant(D)

        super().__init__(K, K_rot, A, B, C, D)
