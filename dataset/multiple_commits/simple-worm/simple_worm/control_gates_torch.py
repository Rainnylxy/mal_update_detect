import torch

from simple_worm.control_gates import ControlGate, ControlGateFenics, ControlGateNumpy


class ControlGateTorch(ControlGate):
    def _configure_gate(self):
        if self.block:
            return 0
        x = torch.linspace(0, 1, self.N)
        g = torch.ones(self.N)
        if self.grad_up is not None:
            g *= 1 / (1 + torch.exp(-self.grad_up * (x - self.offset_up)))
        if self.grad_down is not None:
            g *= 1 / (1 + torch.exp(self.grad_down * (x - self.offset_down)))
        return g

    def clone(self) -> 'ControlGateTorch':
        return ControlGateTorch(**self._init_args)

    def to_fenics(self) -> ControlGateFenics:
        return ControlGateFenics(**self._init_args)

    def to_numpy(self) -> ControlGateNumpy:
        return ControlGateNumpy(**self._init_args)
