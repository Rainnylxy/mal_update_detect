from typing import Tuple

import numpy as np
from simple_worm.controls import ControlSequenceNumpy
from simple_worm.frame import FrameNumpy, FrameSequenceNumpy
from simple_worm.material_parameters import MaterialParametersFenics
from simple_worm.util import estimate_K_from_x
from simple_worm.worm import Worm

# Parameters
N = 100
T = 1
dt = 0.01
K = 2
K_rot = 1
A = 1
B = 0.05
C = 1
D = 0.05
n_timesteps = int(T / dt)

alpha_amplitude = 1
alpha_pref_freq = 1
beta_amplitude = 0.5
beta_pref_freq = 0.5

show_plots = False


def generate_trajectory() -> Tuple[MaterialParametersFenics, FrameNumpy, ControlSequenceNumpy, FrameSequenceNumpy]:
    print('--- Generating trajectory')
    worm = Worm(N, dt=dt)

    # Set material parameters
    MP = MaterialParametersFenics(K, K_rot, A, B, C, D)

    # Create a numpy initial midline along x-axis with twist
    x0 = np.zeros((3, N))
    x0[0] = np.linspace(0, 1 / np.sqrt(2), N, endpoint=True)
    x0[1] = np.linspace(0, 1 / np.sqrt(2), N, endpoint=True)
    psi = np.linspace(start=np.pi - 0.1, stop=np.pi + 0.1, num=N)
    F0 = FrameNumpy(x=x0, psi=psi)

    # Set alpha/beta to propagating sine waves
    alpha = np.zeros((n_timesteps, N))
    beta = np.zeros((n_timesteps, N))
    gamma = np.zeros((n_timesteps, N - 1))
    offset = 0.

    forward_steps = int(n_timesteps / 2)
    backward_steps = n_timesteps - forward_steps

    for i in range(forward_steps):
        if alpha_pref_freq > 0:
            alpha[i] = alpha_amplitude * np.sin(
                alpha_pref_freq * 2 * np.pi * (np.linspace(start=0, stop=1, num=N) - offset)
            )
        if beta_pref_freq > 0:
            beta[i] = beta_amplitude * np.sin(
                beta_pref_freq * 2 * np.pi * (np.linspace(start=0, stop=1, num=N) - offset)
            )
        offset += dt

    for i in range(forward_steps, forward_steps + backward_steps):
        if alpha_pref_freq > 0:
            alpha[i] = alpha_amplitude * np.sin(
                alpha_pref_freq * 2 * np.pi * (np.linspace(start=0, stop=1, num=N) - offset)
            )
        if beta_pref_freq > 0:
            beta[i] = beta_amplitude * np.sin(
                beta_pref_freq * 2 * np.pi * (np.linspace(start=0, stop=1, num=N) - offset)
            )
        offset -= dt

    CS = ControlSequenceNumpy(
        alpha=alpha,
        beta=beta,
        gamma=gamma
    )

    # Run the model forward to generate the output
    FS = worm.solve(T, MP, F0.to_fenics(worm), CS.to_fenics(worm))

    return MP, F0, CS, FS.to_numpy()


def test_K_estimation():
    MP, F0, CS, FS = generate_trajectory()

    if show_plots:
        import matplotlib.pyplot as plt
        from simple_worm.plot3d import plot_CS_vs_output
        plot_CS_vs_output(CS, FS, dt)
        plt.show()

    K_est = estimate_K_from_x(FS, K0=20, verbosity=1)

    print(f'K_actual={K}, K_est={K_est:.3f}')
    assert type(K_est) == float
    assert np.abs(K - K_est) < K * 0.05


if __name__ == '__main__':
    test_K_estimation()
