from typing import List, Tuple, Union, Dict

import torch

from simple_worm.control_gates_torch import ControlGateTorch
from simple_worm.controls import CONTROL_KEYS, ControlsFenics, ControlsNumpy, ControlSequenceFenics, \
    ControlSequenceNumpy
from simple_worm.util_torch import f2t, t2f, t2n, expand_tensor


def controls_fenics_to_torch(self) -> 'ControlsTorch':
    return ControlsTorch(
        alpha=f2t(self.alpha),
        beta=f2t(self.beta),
        gamma=f2t(self.gamma),
    )


def control_sequence_fenics_to_torch(self) -> 'ControlSequenceTorch':
    return ControlSequenceTorch(
        controls=[
            self[t].to_torch()
            for t in range(self.n_timesteps)
        ]
    )


# Extend ControlsFenics and ControlSequenceFenics with helper methods to convert to torch format
ControlsFenics.to_torch = controls_fenics_to_torch
ControlSequenceFenics.to_torch = control_sequence_fenics_to_torch


class ControlsTorch(ControlsNumpy):
    def __init__(
            self,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
            alpha_gate: ControlGateTorch = None,
            beta_gate: ControlGateTorch = None,
            gamma_gate: ControlGateTorch = None,
            worm: 'Worm' = None,
            optimise: bool = False,
    ):
        self.optimise = optimise
        super().__init__(alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm)

    def _init_parameters(self, worm: 'Worm') -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Create default control parameters
        """
        alpha = torch.zeros(worm.N, requires_grad=self.optimise)
        beta = torch.zeros(worm.N, requires_grad=self.optimise)
        gamma = torch.zeros(worm.N - 1, requires_grad=self.optimise)
        return alpha, beta, gamma

    def clone(self) -> 'ControlsTorch':
        return ControlsTorch(
            alpha=self.alpha.clone(),
            beta=self.beta.clone(),
            gamma=self.gamma.clone(),
            alpha_gate=self.alpha_gate.clone() if self.alpha_gate is not None else None,
            beta_gate=self.beta_gate.clone() if self.beta_gate is not None else None,
            gamma_gate=self.gamma_gate.clone() if self.gamma_gate is not None else None,
        )

    def parameters(self, as_dict=False) -> Union[Dict, List]:
        if as_dict:
            return {k: getattr(self, k) for k in CONTROL_KEYS}
        else:
            return [getattr(self, k) for k in CONTROL_KEYS]

    def requires_grad(self) -> bool:
        return any(getattr(self, k).requires_grad for k in CONTROL_KEYS)

    def to_fenics(self, worm: 'Worm') -> ControlsFenics:
        """
        Convert to Fenics
        """
        return ControlsFenics(
            alpha=t2f(self.alpha, fs=worm.V, name='alpha'),
            beta=t2f(self.beta, fs=worm.V, name='beta'),
            gamma=t2f(self.gamma, fs=worm.Q, name='gamma'),
            alpha_gate=self.alpha_gate.to_fenics() if self.alpha_gate is not None else None,
            beta_gate=self.beta_gate.to_fenics() if self.beta_gate is not None else None,
            gamma_gate=self.gamma_gate.to_fenics() if self.gamma_gate is not None else None,
        )

    def to_numpy(self) -> ControlsNumpy:
        """
        Convert to Numpy
        """
        return ControlsNumpy(
            alpha=t2n(self.alpha),
            beta=t2n(self.beta),
            gamma=t2n(self.gamma),
            alpha_gate=self.alpha_gate.to_numpy() if self.alpha_gate is not None else None,
            beta_gate=self.beta_gate.to_numpy() if self.beta_gate is not None else None,
            gamma_gate=self.gamma_gate.to_numpy() if self.gamma_gate is not None else None,
        )

    def __eq__(self, other: 'ControlsTorch') -> bool:
        return all(
            torch.allclose(getattr(self, k), getattr(other, k))
            for k in CONTROL_KEYS
        )


class ControlSequenceTorch(ControlSequenceNumpy):
    def __init__(
            self,
            controls: Union[ControlsTorch, List[ControlsTorch]] = None,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
            alpha_gate: ControlGateTorch = None,
            beta_gate: ControlGateTorch = None,
            gamma_gate: ControlGateTorch = None,
            worm: 'Worm' = None,
            n_timesteps: int = 1,
            optimise: bool = False
    ):
        self.optimise = optimise
        super().__init__(controls, alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm, n_timesteps)

    def _generate_sequence_from_list(self, C: List[ControlsTorch]) -> dict:
        n_timesteps = len(C)
        return {
            k: torch.stack([getattr(C[t], k) for t in range(n_timesteps)])
            for k in CONTROL_KEYS
        }

    def _generate_sequence_from_controls(self, C: ControlsTorch, n_timesteps: int) -> dict:
        # Expand controls across all timesteps
        Cs = {
            k: expand_tensor(getattr(C, k), n_timesteps)
            for k in CONTROL_KEYS
        }
        return Cs

    def _generate_default_controls(self, worm: 'Worm', n_timesteps: int) -> dict:
        C = ControlsTorch(worm=worm, optimise=False)
        Cs = self._generate_sequence_from_controls(C, n_timesteps)
        if self.optimise:
            for k in CONTROL_KEYS:
                Cs[k].requires_grad_(True)
        return Cs

    def requires_grad(self):
        return any(self.controls[k].requires_grad for k in CONTROL_KEYS)

    def parameters(self, include_gates: bool = True, as_dict: bool = False) -> Union[dict, list]:
        params = {k: self.controls[k] for k in CONTROL_KEYS}
        if include_gates:
            params = {**params, **self.get_gates('clone')}
        if as_dict:
            return params
        else:
            return list(params.values())

    def clone(self) -> 'ControlSequenceTorch':
        args = {k: getattr(self, k).clone() for k in CONTROL_KEYS}
        return ControlSequenceTorch(**args, **self.get_gates('clone'))

    def to_numpy(self) -> ControlSequenceNumpy:
        args = {k: t2n(getattr(self, k)) for k in CONTROL_KEYS}
        return ControlSequenceNumpy(**args, **self.get_gates('to_numpy'))

    def __getitem__(self, i) -> ControlsTorch:
        args = {k: self.controls[k][i] for k in CONTROL_KEYS}
        return ControlsTorch(**args, **self.get_gates('clone'))

    def __eq__(self, other: 'ControlSequenceTorch') -> bool:
        abg_equal = all(
            torch.allclose(getattr(self, k), getattr(other, k))
            for k in CONTROL_KEYS
        )
        gates_equal = all(
            getattr(self, f'{k}_gate') == getattr(other, f'{k}_gate')
            for k in CONTROL_KEYS
        )
        return abg_equal and gates_equal


class ControlSequenceBatchTorch(ControlSequenceTorch):
    def __init__(
            self,
            controls: Union[ControlsTorch, List[ControlSequenceTorch]] = None,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
            alpha_gate: ControlGateTorch = None,
            beta_gate: ControlGateTorch = None,
            gamma_gate: ControlGateTorch = None,
            worm: 'Worm' = None,
            n_timesteps: int = 1,
            optimise: bool = False,
            batch_size: int = 1,
    ):
        self.batch_size_init = batch_size
        super().__init__(controls, alpha, beta, gamma, alpha_gate, beta_gate, gamma_gate, worm, n_timesteps, optimise)

    def _generate_batch_from_sequence(self, Cs: dict) -> dict:
        return {
            k: expand_tensor(Cs[k], self.batch_size_init)
            for k in CONTROL_KEYS
        }

    def _generate_sequence_from_list(self, C: List[ControlSequenceTorch]) -> dict:
        batch_size = len(C)
        return {
            k: torch.stack([getattr(C[i], k) for i in range(batch_size)])
            for k in CONTROL_KEYS
        }

    def _generate_sequence_from_controls(self, C: ControlsTorch, n_timesteps: int) -> dict:
        Cs = super()._generate_sequence_from_controls(C, n_timesteps)
        Csb = self._generate_batch_from_sequence(Cs)
        return Csb

    def to_fenics(self, worm: 'Worm') -> List[ControlSequenceFenics]:
        return [
            self[i].to_fenics(worm)
            for i in range(len(self))
        ]

    def to_numpy(self) -> List[ControlSequenceNumpy]:
        return [
            self[i].to_numpy()
            for i in range(len(self))
        ]

    def n_timesteps(self) -> int:
        return len(self.controls['alpha'][0])

    def __getitem__(self, i) -> ControlSequenceTorch:
        args = {k: self.controls[k][i] for k in CONTROL_KEYS}
        return ControlSequenceTorch(**args, **self.get_gates('clone'))

    @staticmethod
    def from_list(batch: List[ControlSequenceTorch], optimise: bool = False) -> 'ControlSequenceBatchTorch':
        args = {
            k: torch.stack([getattr(batch[i], k) for i in range(len(batch))])
            for k in CONTROL_KEYS
        }
        gates = [batch[i].get_gates('clone') for i in range(len(batch))]
        assert all([gi[f'{k}_gate'] == gj[f'{k}_gate']] for k in CONTROL_KEYS for gi, gj in zip(gates, gates)), \
            'Found different control gates in the batch, can only handle a single gate!'
        return ControlSequenceBatchTorch(**args, **gates[0], optimise=optimise)
