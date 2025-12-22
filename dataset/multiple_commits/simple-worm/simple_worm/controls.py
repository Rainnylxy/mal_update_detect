from abc import ABC, abstractmethod
from typing import List, Tuple, Union, Optional, Dict

import numpy as np
from fenics import *

from simple_worm.control_gates import ControlGate, ControlGateFenics, ControlGateNumpy

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass

from simple_worm.util import v2f, expand_numpy, f2n

CONTROL_KEYS = ['alpha', 'beta', 'gamma']


class Controls(ABC):
    """
    The worm is controlled with 3 forces (controls) acting along the body; alpha, beta and gamma.
    """

    def __init__(
            self,
            alpha=None,
            beta=None,
            gamma=None,
            alpha_gate: ControlGate = None,
            beta_gate: ControlGate = None,
            gamma_gate: ControlGate = None,
            worm: 'Worm' = None
    ):
        if worm is None:
            # If no worm object passed then require all controls to be defined
            assert all(abg is not None for abg in [alpha, beta, gamma])
        else:
            # Otherwise, require no controls to be passed
            assert all(abg is None for abg in [alpha, beta, gamma])
            alpha, beta, gamma = self._init_parameters(worm)

        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

        # Validate
        self._check_shapes()

        # Control gates
        self.alpha_gate = alpha_gate
        self.beta_gate = beta_gate
        self.gamma_gate = gamma_gate

    def get_alpha(self):
        """Get gated alpha."""
        if self.alpha_gate is not None:
            return self.alpha_gate(self.alpha)
        return self.alpha

    def get_beta(self):
        """Get gated beta."""
        if self.beta_gate is not None:
            return self.beta_gate(self.beta)
        return self.beta

    def get_gamma(self):
        """Get gated gamma."""
        if self.gamma_gate is not None:
            return self.gamma_gate(self.gamma)
        return self.gamma

    def is_gated(self, k) -> bool:
        return getattr(self, f'{k}_gate') is not None

    def get_gates(self, apply: str = None) -> Dict[str, Optional[Union[ControlGate]]]:
        gates = {}
        for k in CONTROL_KEYS:
            gk = f'{k}_gate'
            gate = getattr(self, gk)
            if gate is not None and apply is not None:
                gate = getattr(gate, apply)()
            gates[gk] = gate
        return gates

    @abstractmethod
    def _init_parameters(self, worm: 'Worm') -> Tuple:
        """
        Return alpha, beta, gamma in appropriate format.
        """
        pass

    @abstractmethod
    def _check_shapes(self):
        pass

    @abstractmethod
    def clone(self) -> 'Controls':
        pass

    @abstractmethod
    def __eq__(self, other: 'Controls') -> bool:
        pass


class ControlsFenics(Controls):
    def __init__(
            self,
            alpha: Function = None,
            beta: Function = None,
            gamma: Function = None,
            alpha_gate: ControlGateFenics = None,
            beta_gate: ControlGateFenics = None,
            gamma_gate: ControlGateFenics = None,
            worm: 'Worm' = None,
    ):
        super().__init__(alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm)

    def _init_parameters(self, worm: 'Worm') -> Tuple[Function, Function, Function]:
        """
        Use default parameters as set in the base Worm instance.
        """
        alpha = v2f(val=worm.alpha_pref_default, fs=worm.V, name='alpha')
        beta = v2f(val=worm.beta_pref_default, fs=worm.V, name='beta')
        gamma = v2f(val=worm.gamma_pref_default, fs=worm.Q, name='gamma')
        return alpha, beta, gamma

    def _check_shapes(self):
        assert self.alpha.function_space() == self.beta.function_space(), 'Function spaces differ from alpha to beta'
        # todo: check gamma?

    def clone(self) -> 'ControlsFenics':
        V = self.alpha.function_space()
        Q = self.gamma.function_space()
        return ControlsFenics(
            alpha=project(self.alpha, V),
            beta=project(self.beta, V),
            gamma=project(self.gamma, Q),
            **self.get_gates('clone')
        )

    def to_numpy(self) -> 'ControlsNumpy':
        args = {k: f2n(getattr(self, k)) for k in CONTROL_KEYS}
        return ControlsNumpy(**args, **self.get_gates('to_numpy'))

    def __eq__(self, other: 'ControlsFenics') -> bool:
        # Convert to numpy for equality check
        c1 = self.to_numpy()
        c2 = other.to_numpy()
        return c1 == c2


class ControlsNumpy(Controls):
    def __init__(
            self,
            alpha: np.ndarray = None,
            beta: np.ndarray = None,
            gamma: np.ndarray = None,
            alpha_gate: ControlGateNumpy = None,
            beta_gate: ControlGateNumpy = None,
            gamma_gate: ControlGateNumpy = None,
            worm: 'Worm' = None,
    ):
        super().__init__(alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm)

    def _init_parameters(self, worm: 'Worm') -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Default forces to empty arrays.
        """
        alpha = np.zeros(worm.N)
        beta = np.zeros(worm.N)
        gamma = np.zeros(worm.N - 1)
        return alpha, beta, gamma

    def _check_shapes(self):
        assert self.alpha.shape == self.beta.shape
        assert self.alpha.shape[-1] == self.gamma.shape[-1] + 1

    def clone(self) -> 'ControlsNumpy':
        args = {k: getattr(self, k).copy() for k in CONTROL_KEYS}
        return ControlsNumpy(**args, **self.get_gates('clone'))

    def to_fenics(self, worm: 'Worm') -> ControlsFenics:
        """
        Convert to Fenics
        """
        return ControlsFenics(
            alpha=v2f(self.alpha, fs=worm.V, name='alpha'),
            beta=v2f(self.beta, fs=worm.V, name='beta'),
            gamma=v2f(self.gamma, fs=worm.Q, name='gamma'),
            **self.get_gates('to_fenics'),
        )

    def __eq__(self, other: 'ControlsNumpy') -> bool:
        abg_equal = all(
            np.allclose(getattr(self, k), getattr(other, k))
            for k in CONTROL_KEYS
        )
        gates_equal = all(
            getattr(self, f'{k}_gate') == getattr(other, f'{k}_gate')
            for k in CONTROL_KEYS
        )
        return abg_equal and gates_equal


class ControlSequence(ABC):
    def __init__(
            self,
            controls: Union[Controls, List[Controls]] = None,
            alpha=None,
            beta=None,
            gamma=None,
            alpha_gate: ControlGate = None,
            beta_gate: ControlGate = None,
            gamma_gate: ControlGate = None,
            worm: 'Worm' = None,
            n_timesteps: int = 1
    ):
        # Set gates first as they may be copied into lists
        self.alpha_gate = alpha_gate
        self.beta_gate = beta_gate
        self.gamma_gate = gamma_gate

        if worm is None:
            # If no worm object passed then require all controls to be defined
            if controls is not None:
                # ..either with controls and no abg
                assert all(abg is None for abg in [alpha, beta, gamma])
                if type(controls) == list:
                    # Controls are given as a time-indexed list
                    controls = self._generate_sequence_from_list(controls)
                else:
                    # Controls are just a single example which will need expanding
                    controls = self._generate_sequence_from_controls(controls, n_timesteps)
            else:
                # ..or in component form, with no control list
                assert all(abg is not None for abg in [alpha, beta, gamma])
                assert len(alpha) == len(beta) == len(gamma)
                controls = self._generate_sequence_from_components(alpha, beta, gamma)
        else:
            assert controls is None and all(abg is None for abg in [alpha, beta, gamma])
            controls = self._generate_default_controls(worm, n_timesteps)

        self.controls = controls

    def is_gated(self, k) -> bool:
        return getattr(self, f'{k}_gate') is not None

    def get_gates(self, apply: str = None) -> Dict[str, Optional[Union[ControlGate]]]:
        gates = {}
        for k in CONTROL_KEYS:
            gk = f'{k}_gate'
            gate = getattr(self, gk)
            if gate is not None and apply is not None:
                gate = getattr(gate, apply)()
            gates[gk] = gate
        return gates

    @abstractmethod
    def _generate_sequence_from_list(self, C: List[Controls]):
        pass

    @abstractmethod
    def _generate_sequence_from_controls(self, C: Controls, n_timesteps: int):
        pass

    @abstractmethod
    def _generate_sequence_from_components(self, alpha, beta, gamma):
        pass

    @abstractmethod
    def _generate_default_controls(self, worm: 'Worm', n_timesteps: int):
        pass

    @abstractmethod
    def clone(self) -> 'ControlSequence':
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass

    @abstractmethod
    def __getitem__(self, i) -> Controls:
        pass

    @abstractmethod
    def __eq__(self, other: 'ControlSequence') -> bool:
        pass

    @property
    def n_timesteps(self) -> int:
        return len(self)


class ControlSequenceFenics(ControlSequence):
    def __init__(
            self,
            controls: Union[ControlsFenics, List[ControlsFenics]] = None,
            alpha: List[Function] = None,
            beta: List[Function] = None,
            gamma: List[Function] = None,
            alpha_gate: ControlGateFenics = None,
            beta_gate: ControlGateFenics = None,
            gamma_gate: ControlGateFenics = None,
            worm: 'Worm' = None,
            n_timesteps: int = 1
    ):
        super().__init__(controls, alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm, n_timesteps)

    def _generate_sequence_from_list(self, C: List[ControlsFenics]) -> List[ControlsFenics]:
        # A ControlSequence in fenics is just a list of Controls objects
        return C

    def _generate_sequence_from_controls(self, C: ControlsFenics, n_timesteps: int):
        args = {k: getattr(C, k) for k in CONTROL_KEYS}
        for k in CONTROL_KEYS:
            gk = f'{k}_gate'
            gate = getattr(C, gk)
            if gate is None:
                gate = getattr(self, gk)
            args[gk] = gate.clone() if gate is not None else None
        Cs = [
            ControlsFenics(**args)
            for _ in range(n_timesteps)
        ]
        return Cs

    def _generate_sequence_from_components(
            self,
            alpha: List[Function],
            beta: List[Function],
            gamma: List[Function]
    ) -> List[ControlsFenics]:
        Cs = [
            ControlsFenics(
                alpha=alpha[t],
                beta=beta[t],
                gamma=gamma[t]
            )
            for t in range(len(alpha))
        ]
        return Cs

    def _generate_default_controls(self, worm: 'Worm', n_timesteps: int):
        Cs = [
            ControlsFenics(worm=worm)
            for _ in range(n_timesteps)
        ]
        return Cs

    def clone(self) -> 'ControlSequenceFenics':
        controls = [C.clone() for C in self.controls]
        return ControlSequenceFenics(controls=controls, **self.get_gates('clone'))

    def to_numpy(self) -> 'ControlsSequenceNumpy':
        return ControlSequenceNumpy(
            controls=[
                self[t].to_numpy()
                for t in range(len(self.controls))
            ],
            **self.get_gates('to_numpy')
        )

    def __len__(self) -> int:
        return len(self.controls)

    def __getitem__(self, i) -> ControlsFenics:
        return self.controls[i]

    def __eq__(self, other: 'ControlSequenceFenics') -> bool:
        cs1 = self.to_numpy()
        cs2 = other.to_numpy()
        return cs1 == cs2


class ControlSequenceNumpy(ControlSequence):
    def __init__(
            self,
            controls: Union[ControlsNumpy, List[ControlsNumpy]] = None,
            alpha: np.ndarray = None,
            beta: np.ndarray = None,
            gamma: np.ndarray = None,
            alpha_gate: ControlGateNumpy = None,
            beta_gate: ControlGateNumpy = None,
            gamma_gate: ControlGateNumpy = None,
            worm: 'Worm' = None,
            n_timesteps: int = 1
    ):
        super().__init__(controls, alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm, n_timesteps)

    def _generate_sequence_from_list(self, C: List[ControlsNumpy]) -> dict:
        n_timesteps = len(C)
        return {
            k: np.stack([getattr(C[t], k) for t in range(n_timesteps)])
            for k in CONTROL_KEYS
        }

    def _generate_sequence_from_controls(self, C: ControlsNumpy, n_timesteps: int) -> dict:
        # Expand controls across all timesteps
        Cs = {
            k: expand_numpy(getattr(C, k), n_timesteps)
            for k in CONTROL_KEYS
        }
        return Cs

    def _generate_sequence_from_components(
            self,
            alpha: np.ndarray,
            beta: np.ndarray,
            gamma: np.ndarray
    ) -> dict:
        return {
            'alpha': alpha,
            'beta': beta,
            'gamma': gamma,
        }

    def _generate_default_controls(self, worm: 'Worm', n_timesteps: int) -> dict:
        C = ControlsNumpy(worm=worm)
        Cs = self._generate_sequence_from_controls(C, n_timesteps)
        return Cs

    def to_fenics(self, worm: 'Worm') -> ControlSequenceFenics:
        CSF = [
            self[t].to_fenics(worm)
            for t in range(self.n_timesteps)
        ]
        return ControlSequenceFenics(controls=CSF, **self.get_gates('to_fenics'))

    def clone(self) -> 'ControlSequenceNumpy':
        args = {k: getattr(self, k).copy() for k in CONTROL_KEYS}
        return ControlSequenceNumpy(**args, **self.get_gates('clone'))

    def __len__(self) -> int:
        return len(self.controls['alpha'])

    def __getitem__(self, i) -> ControlsNumpy:
        args = {k: self.controls[k][i] for k in CONTROL_KEYS}
        return ControlsNumpy(**args, **self.get_gates('clone'))

    def __getattr__(self, k):
        if k in CONTROL_KEYS:
            # Apply gate
            g = getattr(self, f'{k}_gate')
            if g is not None:
                return g(self.controls[k])
            return self.controls[k]
        else:
            raise AttributeError(f'Key: "{k}" not found.')

    def __eq__(self, other: 'ControlSequenceNumpy') -> bool:
        abg_equal = all(
            np.allclose(getattr(self, k), getattr(other, k))
            for k in CONTROL_KEYS
        )
        gates_equal = all(
            getattr(self, f'{k}_gate') == getattr(other, f'{k}_gate')
            for k in CONTROL_KEYS
        )
        return abg_equal and gates_equal
