from typing import List, Tuple, Union

import numpy as np
import torch
from simple_worm.frame import FrameFenics, FrameNumpy, Frame, FRAME_KEYS, FrameSequenceFenics, FrameSequenceNumpy
from simple_worm.util import estimate_psi_from_x, PSI_ESTIMATE_WS_DEFAULT
from simple_worm.util_torch import f2t, t2f, t2n, expand_tensor


def frame_fenics_to_torch(self) -> 'FrameTorch':
    self.project_outputs()
    args = {k: f2t(getattr(self, k)) for k in FRAME_KEYS}
    return FrameTorch(**args)


def frame_sequence_fenics_to_torch(self) -> 'FrameSequenceTorch':
    return FrameSequenceTorch(
        frames=[
            self[t].to_torch()
            for t in range(self.n_frames)
        ]
    )


# Extend FrameFenics and FrameSequenceFenics with helper methods to convert to torch
FrameFenics.to_torch = frame_fenics_to_torch
FrameSequenceFenics.to_torch = frame_sequence_fenics_to_torch


class FrameTorch(Frame):
    def __init__(
            self,
            x: torch.Tensor = None,
            psi: torch.Tensor = None,
            e0: torch.Tensor = None,
            e1: torch.Tensor = None,
            e2: torch.Tensor = None,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
            worm: 'Worm' = None,
            estimate_psi: bool = False,
            estimate_psi_window_size: float = PSI_ESTIMATE_WS_DEFAULT,
            optimise: bool = False
    ):
        self.optimise = optimise
        super().__init__(x, psi, e0, e1, e2, alpha, beta, gamma, worm, estimate_psi, estimate_psi_window_size)

        # Ensure psi is in the range [-pi, pi]
        # self.psi.data = torch.remainder(self.psi, 2 * np.pi)

        # Ensure psi requires grad if needed
        if self.optimise:
            self.psi.requires_grad = True

    def _init_x(self, worm: 'Worm') -> torch.Tensor:
        shape = (3, worm.N)
        x = torch.zeros(shape)
        return x

    def _init_psi(self, worm: 'Worm' = None, estimate: bool = False, window_size: float = PSI_ESTIMATE_WS_DEFAULT) \
            -> torch.Tensor:
        if estimate:
            psi = estimate_psi_from_x(self.x, window_size)
            psi = torch.from_numpy(psi)
            if self.optimise:
                psi.requires_grad = True
        else:
            if worm is None:
                N = self.x.shape[-1]
            else:
                N = worm.N
            psi = torch.zeros(N, requires_grad=self.optimise)
        return psi

    def _init_components(self) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        shape = self.x.shape
        e0 = torch.zeros(shape)
        e1 = torch.zeros(shape)
        e2 = torch.zeros(shape)
        return e0, e1, e2

    def _init_curvature_and_twist(self, worm: 'Worm' = None) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        if worm is None:
            N = self.x.shape[-1]
        else:
            N = worm.N
        alpha = torch.zeros(N)
        beta = torch.zeros(N)
        gamma = torch.zeros(N - 1)
        return alpha, beta, gamma

    def requires_grad(self) -> bool:
        return self.psi.requires_grad

    def to_fenics(self, worm: 'Worm', calculate_components: bool = False) -> FrameFenics:
        return FrameFenics(
            x=t2f(self.x, fs=worm.V3, name='x'),
            psi=t2f(self.psi, fs=worm.V, name='psi'),
            e0=t2f(self.e0, fs=worm.V3, name='e0'),
            e1=t2f(self.e1, fs=worm.V3, name='e1'),
            e2=t2f(self.e2, fs=worm.V3, name='e2'),
            alpha=t2f(self.alpha, fs=worm.V, name='alpha'),
            beta=t2f(self.beta, fs=worm.V, name='beta'),
            gamma=t2f(self.gamma, fs=worm.Q, name='gamma'),
            worm=worm,
            calculate_components=calculate_components
        )

    def to_numpy(self, worm: 'Worm' = None, calculate_components: bool = False) -> FrameNumpy:
        if calculate_components:
            assert worm is not None
            FF = self.to_fenics(worm=worm, calculate_components=True)
            return FF.to_numpy()
        args = {k: t2n(getattr(self, k)) for k in FRAME_KEYS}
        return FrameNumpy(**args)

    def clone(self) -> 'FrameTorch':
        args = {k: getattr(self, k).clone() for k in FRAME_KEYS}
        return FrameTorch(**args)

    def parameters(self, as_dict: bool = False) -> Union[dict, list]:
        if as_dict:
            return {k: getattr(self, k) for k in FRAME_KEYS}
        else:
            return [getattr(self, k) for k in FRAME_KEYS]

    def __eq__(self, other: 'FrameTorch') -> bool:
        return all(
            torch.allclose(getattr(self, k), getattr(other, k))
            for k in FRAME_KEYS
        )


class FrameBatchTorch(FrameTorch):
    def __init__(
            self,
            x: torch.Tensor = None,
            psi: torch.Tensor = None,
            e0: torch.Tensor = None,
            e1: torch.Tensor = None,
            e2: torch.Tensor = None,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
            worm: 'Worm' = None,
            estimate_psi: bool = False,
            estimate_psi_window_size: float = PSI_ESTIMATE_WS_DEFAULT,
            optimise: bool = False,
            batch_size: int = None
    ):
        self.batch_size_init = batch_size
        super().__init__(x, psi, e0, e1, e2, alpha, beta, gamma, worm, estimate_psi, estimate_psi_window_size, optimise)

    def _init_x(self, worm: 'Worm') -> torch.Tensor:
        return expand_tensor(
            super()._init_x(worm),
            self.batch_size_init
        )

    def _init_psi(self, worm: 'Worm' = None, estimate: bool = False, window_size: float = PSI_ESTIMATE_WS_DEFAULT) \
            -> torch.Tensor:
        if worm is None:
            N = self.x.shape[-1]
        else:
            N = worm.N
        shape = (self.batch_size, N)
        psi = torch.zeros(shape, requires_grad=self.optimise)
        if estimate:
            for i in range(self.batch_size):
                psi.data[i] = torch.from_numpy(
                    estimate_psi_from_x(self.x[i], window_size)
                )
        return psi

    def _init_curvature_and_twist(self, worm: 'Worm' = None) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        if worm is None:
            N = self.x.shape[-1]
        else:
            N = worm.N
        alpha = torch.zeros((self.batch_size, N))
        beta = torch.zeros((self.batch_size, N))
        gamma = torch.zeros((self.batch_size, N - 1))
        return alpha, beta, gamma

    def __getitem__(self, i) -> FrameTorch:
        args = {k: getattr(self, k)[i] for k in FRAME_KEYS}
        return FrameTorch(**args)

    def clone(self) -> 'FrameBatchTorch':
        args = {k: getattr(self, k).clone() for k in FRAME_KEYS}
        return FrameBatchTorch(**args)

    @property
    def batch_size(self) -> int:
        return len(self.x)

    def __len__(self) -> int:
        return len(self.x)

    @staticmethod
    def from_list(batch: List[FrameTorch], optimise: bool = False) -> 'FrameBatchTorch':
        args = {
            k: torch.stack([getattr(batch[i], k) for i in range(len(batch))])
            for k in FRAME_KEYS
        }
        return FrameBatchTorch(**args, optimise=optimise)


class FrameSequenceTorch(FrameSequenceNumpy):
    def __init__(
            self,
            frames: List[FrameTorch] = None,
            x: torch.Tensor = None,
            psi: torch.Tensor = None,
            e0: torch.Tensor = None,
            e1: torch.Tensor = None,
            e2: torch.Tensor = None,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
    ):
        super().__init__(frames, x, psi, e0, e1, e2, alpha, beta, gamma)

    def _generate_sequence_from_list(self, frames: List[FrameTorch]) -> dict:
        n_timesteps = len(frames)
        return {
            k: torch.stack([getattr(frames[t], k) for t in range(n_timesteps)])
            for k in FRAME_KEYS
        }

    def parameters(self, as_dict: bool = False) -> Union[dict, list]:
        if as_dict:
            return {k: self.frames[k] for k in FRAME_KEYS}
        else:
            return [self.frames[k] for k in FRAME_KEYS]

    def clone(self) -> 'FrameSequenceTorch':
        args = {
            k: self.frames[k].clone() if self.frames[k] is not None else None
            for k in FRAME_KEYS
        }
        return FrameSequenceTorch(**args)

    def to_numpy(self) -> FrameSequenceNumpy:
        args = {
            k: t2n(getattr(self, k))
            for k in FRAME_KEYS if getattr(self, k) is not None
        }
        return FrameSequenceNumpy(**args)

    def __getitem__(self, i) -> Union['FrameSequenceTorch', FrameTorch]:
        if type(i) == slice:
            frames = []
            for j in range(i.start, i.stop):
                frames.append(self[j])
            return FrameSequenceTorch(frames=frames)
        elif type(i) == int:
            args = {
                k: self.frames[k][i] if self.frames[k] is not None else None
                for k in FRAME_KEYS
            }
            return FrameTorch(**args)
        else:
            raise ValueError(f'Unrecognised accessor type: {type(i)}.')

    def __eq__(self, other: 'FrameSequenceTorch') -> bool:
        return all(
            torch.allclose(getattr(self, k), getattr(other, k))
            for k in FRAME_KEYS
        )


class FrameSequenceBatchTorch(FrameSequenceTorch):
    def __init__(
            self,
            frames: List[FrameSequenceTorch] = None,
            x: torch.Tensor = None,
            psi: torch.Tensor = None,
            e0: torch.Tensor = None,
            e1: torch.Tensor = None,
            e2: torch.Tensor = None,
            alpha: torch.Tensor = None,
            beta: torch.Tensor = None,
            gamma: torch.Tensor = None,
            batch_size: int = 1,
    ):
        self.batch_size_init = batch_size
        super().__init__(frames, x, psi, e0, e1, e2, alpha, beta, gamma)

    def _generate_batch_from_sequence(self, Fs: dict) -> dict:
        return {
            k: expand_tensor(Fs[k], self.batch_size_init)
            for k in FRAME_KEYS
        }

    def _generate_sequence_from_list(self, frames: List[FrameSequenceTorch]) -> dict:
        batch_size = len(frames)
        return {
            k: torch.stack([getattr(frames[i], k) for i in range(batch_size)])
            for k in FRAME_KEYS if frames[i] is not None
        }

    def to_fenics(self, worm: 'Worm', calculate_components=False) -> List[FrameSequenceFenics]:
        return [
            self[i].to_fenics(worm, calculate_components)
            for i in range(len(self))
        ]

    def to_numpy(self) -> List[FrameSequenceNumpy]:
        return [
            self[i].to_numpy()
            for i in range(len(self))
        ]

    def n_frames(self) -> int:
        return len(self[0])

    def __getitem__(self, i) -> FrameSequenceTorch:
        args = {k: self.frames[k][i] for k in FRAME_KEYS if self.frames[k] is not None}
        return FrameSequenceTorch(**args)

    @staticmethod
    def from_list(batch: List[FrameSequenceTorch]) -> 'FrameSequenceBatchTorch':
        args = {
            k: torch.stack([getattr(batch[i], k) for i in range(len(batch))])
            for k in FRAME_KEYS if getattr(batch[0], k) is not None
        }
        return FrameSequenceBatchTorch(**args)
