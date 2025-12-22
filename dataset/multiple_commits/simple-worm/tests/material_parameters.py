from typing import Tuple

import numpy as np
import pytest

from simple_worm.controls import ControlSequenceNumpy
from simple_worm.frame import FrameNumpy
from simple_worm.material_parameters import MaterialParameters, MaterialParametersFenics
from simple_worm.worm import Worm

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    # Needs importing here to line up with the imports in worm.py when both modules
    # are installed (even though not strictly required here).
    pass

# Parameters
N = 40
T = 1
dt = 0.1
n_timesteps = int(T / dt)

alpha_amplitude = 3
beta_amplitude = 3
alpha_pref_freq = 0.5
beta_pref_freq = 0.5

FPS = 10


def _setup() -> Tuple[Worm, FrameNumpy, ControlSequenceNumpy]:
    worm = Worm(N, dt)

    # Create a numpy initial midline along x-axis with twist
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    psi = np.linspace(start=np.pi - 0.1, stop=np.pi + 0.1, num=N)
    F0 = FrameNumpy(x=x0, psi=psi)

    # Set alpha/beta to propagating sine waves
    alpha = np.zeros((n_timesteps, N))
    beta = np.zeros((n_timesteps, N))
    gamma = np.zeros((n_timesteps, N - 1))
    offset = 0.
    for i in range(n_timesteps):
        if alpha_pref_freq > 0:
            alpha[i] = alpha_amplitude * np.sin(
                alpha_pref_freq * 2 * np.pi * (np.linspace(start=0, stop=1, num=N) - offset)
            )
        if beta_pref_freq > 0:
            beta[i] = beta_amplitude * np.sin(
                beta_pref_freq * 2 * np.pi * (np.linspace(start=0, stop=1, num=N) - offset)
            )
        offset += dt
    CS = ControlSequenceNumpy(
        alpha=alpha,
        beta=beta,
        gamma=gamma
    )

    return worm, F0, CS


def check_defaults():
    import matplotlib.pyplot as plt
    from simple_worm.plot3d import plot_CS, generate_interactive_scatter_clip
    worm, F0, CS = _setup()

    # Show the controls
    plot_CS(CS)
    plt.show()

    # Run the sim and display a 3D clip
    MP = MaterialParametersFenics(K=2)
    FS = worm.solve(T, MP, F0.to_fenics(worm), CS.to_fenics(worm))
    generate_interactive_scatter_clip(FS.to_numpy(), fps=FPS)


def sweep_parameters():
    import matplotlib.pyplot as plt
    from simple_worm.plot3d import plot_CS_vs_output

    for K in [10, 5, 2]:
        for A in [10, 1, 0.1]:
            for B in [10, 1, 0.1, 0]:
                for C in [10, 1, 0.1]:
                    for D in [10, 1, 0.1, 0]:
                        worm, F0, CS = _setup()
                        MP = MaterialParameters(K=K, A=A, B=B, C=C, D=D)

                        # Run the sim and display a 3D clip
                        FS = worm.solve(T, MP, F0.to_fenics(worm), CS.to_fenics(worm))

                        # Show controls and curvatures
                        fig = plot_CS_vs_output(CS, FS.to_numpy(), dt)
                        fig.suptitle(f'K={K}, A={A}, B={B}, C={C}, D={D}')
                        fig.tight_layout()
                        plt.show()


def test_invalid_parameters():
    bad_params = {
        'K': 0,
        'K': 0.99,
        'K': 1001,
        'K_rot': 0,
        'K_rot': 101,
        'A': 0,
        'A': -1,
        'A': 101,
        'B': -1,
        'B': 11,
        'C': 0,
        'C': -1,
        'C': 101,
        'D': -1,
        'D': 11,
    }

    for k, v in bad_params.items():
        with pytest.raises(AssertionError):
            MaterialParameters(**{k: v})


def make_clips_varying_K():
    from simple_worm.plot3d import generate_interactive_scatter_clip
    for K in [10, 5, 2, 1.1]:
        worm, F0, CS = _setup()
        MP = MaterialParameters(K=K)
        FS = worm.solve(T, MP, F0.to_fenics(worm), CS.to_fenics(worm))
        ani = generate_interactive_scatter_clip(FS.to_numpy(), fps=FPS, show=False)
        ani.save(f'K={K}.mp4', writer='ffmpeg', fps=FPS)


if __name__ == '__main__':
    check_defaults()
    test_invalid_parameters()
    make_clips_varying_K()
    sweep_parameters()
