from abc import ABC, abstractmethod

import numpy as np
from fenics import *

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass


class ControlGate(ABC):
    """
    Gate to apply to some control variable.
    """

    def __init__(
            self,
            N: int,
            block: bool = False,
            grad_up: float = None,
            offset_up: float = None,
            grad_down: float = None,
            offset_down: float = None,
    ):
        if block:
            assert all([v is None] for v in [grad_up, offset_up, grad_down, offset_down]), \
                'A block gate cannot have any additional arguments.'
        assert not (grad_up is None and offset_up is not None) \
               and not (grad_up is not None and offset_up is None), \
            'grad_up and offset_up must be defined together.'
        assert not (grad_down is None and offset_down is not None) \
               and not (grad_down is not None and offset_down is None), \
            'grad_down and offset_down must be defined together.'
        if grad_up is not None:
            assert grad_up > 0, 'grad_up must be > 0.'
            assert 0 <= offset_up <= 1, 'offset_up must be between 0 and 1.'
        if grad_down is not None:
            assert grad_down > 0, 'grad_down must be > 0.'
            assert 0 <= offset_down <= 1, 'offset_down must be between 0 and 1.'

        self.N = N
        self.block = block
        self.grad_up = grad_up
        self.offset_up = offset_up
        self.grad_down = grad_down
        self.offset_down = offset_down
        self.gate = self._configure_gate()

    def __call__(self, control):
        return self.gate * control

    @property
    def _init_args(self) -> dict:
        return {
            'N': self.N,
            'block': self.block,
            'grad_up': self.grad_up,
            'offset_up': self.offset_up,
            'grad_down': self.grad_down,
            'offset_down': self.offset_down
        }

    @abstractmethod
    def _configure_gate(self):
        pass

    @abstractmethod
    def clone(self):
        pass

    def __eq__(self, other: 'ControlGate'):
        if other is None:
            return False
        return self._init_args == other._init_args


class ControlGateFenics(ControlGate):
    def _configure_gate(self) -> Expression:
        if self.block:
            return Expression('v', v=0, degree=1)
        g = Expression('v', v=1, degree=1)
        if self.grad_up is not None:
            g *= Expression('1/(1+exp(g*(x[0]-k)))', degree=1, g=self.grad_up, k=self.offset_up)
        if self.grad_down is not None:
            g *= Expression('1/(1+exp(-g*(x[0]-k)))', degree=1, g=self.grad_down, k=self.offset_down)
        return g

    def clone(self) -> 'ControlGateFenics':
        return ControlGateFenics(**self._init_args)

    def to_numpy(self) -> 'ControlGateNumpy':
        return ControlGateNumpy(**self._init_args)

    def __call__(self, control) -> Function:
        return project(self.gate * control, control.function_space())


class ControlGateNumpy(ControlGate):
    def _configure_gate(self):
        if self.block:
            return 0
        x = np.linspace(0, 1, self.N)
        g = np.ones(self.N)
        if self.grad_up is not None:
            g *= 1 / (1 + np.exp(-self.grad_up * (x - self.offset_up)))
        if self.grad_down is not None:
            g *= 1 / (1 + np.exp(self.grad_down * (x - self.offset_down)))
        return g

    def clone(self) -> 'ControlGateNumpy':
        return ControlGateNumpy(**self._init_args)

    def to_fenics(self) -> 'ControlGateFenics':
        return ControlGateFenics(**self._init_args)
