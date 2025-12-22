from typing import Tuple, Union

import numpy as np

from simple_worm.frame import FrameSequenceNumpy, FrameNumpy


def generate_test_target(
        N: int = 10,
        T: float = 0.1,
        dt: float = 0.1,
        batch_size: int = 1,
        alpha_pref_freq: float = 1.,
        beta_pref_freq: float = 0.,
) -> Tuple['MaterialParametersBatchTorch', 'FrameBatchTorch', 'ControlSequenceBatchTorch', 'FrameSequenceBatchTorch']:
    import torch
    from simple_worm.controls_torch import ControlSequenceBatchTorch
    from simple_worm.frame_torch import FrameBatchTorch
    from simple_worm.material_parameters_torch import MaterialParametersBatchTorch, MaterialParametersTorch
    from simple_worm.worm_torch import WormModule

    print('--- Generating test target')
    worm = WormModule(N, dt=dt, batch_size=batch_size)
    n_timesteps = int(T / dt)

    # Set material parameters
    MPi = MaterialParametersTorch(K=2)
    MPb = torch.repeat_interleave(MPi.parameter_vector().unsqueeze(dim=1), batch_size, dim=1)
    MP = MaterialParametersBatchTorch(*MPb)

    # Set initial frame
    x0 = torch.zeros((batch_size, 3, N), dtype=torch.float64)
    x0[:, 0] = torch.linspace(start=0, end=1 / np.sqrt(2), steps=N)
    x0[:, 1] = torch.linspace(start=0, end=1 / np.sqrt(2), steps=N)
    psi0 = torch.zeros((batch_size, N), dtype=torch.float64)
    psi0[:] = torch.linspace(start=0, end=np.pi, steps=N)
    F0 = FrameBatchTorch(x=x0, psi=psi0)

    # Set controls
    CS = ControlSequenceBatchTorch(
        worm=worm.worm_solver,
        n_timesteps=n_timesteps,
        batch_size=batch_size
    )

    # Set alpha/beta to propagating sine waves
    offset = 0.
    for i in range(n_timesteps):
        if alpha_pref_freq > 0:
            CS.alpha[:, i] = 2 * torch.sin(
                alpha_pref_freq * 2 * np.pi * (torch.linspace(start=0, end=1, steps=N) + offset)
            )
        if beta_pref_freq > 0:
            CS.beta[:, i] = torch.sin(
                beta_pref_freq * 2 * np.pi * (torch.linspace(start=0, end=1, steps=N) + offset)
            )
        offset += dt

    # Add a slight twist along the body
    eps = 1e-2
    CS.gamma[:] = torch.linspace(start=-eps, end=eps, steps=N - 1)

    # Run the model forward to generate the output
    FS, L = worm.forward(MP, F0, CS)

    return MP, F0, CS, FS


def psi_diff(F1: Union[FrameNumpy, FrameSequenceNumpy], F2: Union[FrameNumpy, FrameSequenceNumpy]):
    # Return minimum of +0, +pi, +2pi (%2pi) differences to account for circular boundary
    return np.min(
        np.array([
            np.abs(F1.psi - F2.psi),
            np.abs((F1.psi + np.pi) % (2 * np.pi) - (F2.psi + np.pi) % (2 * np.pi)),
            np.abs((F1.psi + 2 * np.pi) % (2 * np.pi) - (F2.psi + 2 * np.pi) % (2 * np.pi))
        ]),
        axis=0
    )
