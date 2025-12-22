import time
from datetime import timedelta
from typing import Tuple

import numpy as np
from simple_worm.controls import ControlSequenceNumpy
from simple_worm.frame import FrameNumpy
from simple_worm.material_parameters import MaterialParametersFenics
from simple_worm.worm import Worm

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    # Needs importing here to line up with the imports in worm.py when both modules
    # are installed (even though not strictly required here).
    pass

# Parameters
N = 100
T = 0.005
dt = 0.0001
n_timesteps = int(T / dt)

alpha_amplitude = 3
beta_amplitude = 3
alpha_pref_freq = 0.5
beta_pref_freq = 0.5

all_solvers = ['bicgstab', 'cg', 'default', 'gmres', 'minres', 'mumps', 'petsc', 'richardson', 'superlu',
               'superlu_dist', 'tfqmr', 'umfpack']
all_preconditioners = ['amg', 'default', 'hypre_amg', 'hypre_euclid', 'hypre_parasails', 'icc', 'ilu', 'jacobi', 'none']

exclude_solvers = ['bicgstab', 'cg', 'default', 'gmres', 'minres', 'petsc', 'richardson', 'superlu_dist', 'tfqmr']
exclude_preconditioners = ['amg', 'hypre_amg', 'hypre_euclid', 'hypre_parasails']

solvers = [s for s in all_solvers if s not in exclude_solvers]
preconditioners = [p for p in all_preconditioners if p not in exclude_preconditioners]


def _setup() -> Tuple[Worm, MaterialParametersFenics, FrameNumpy, ControlSequenceNumpy]:
    worm = Worm(N, dt, quiet=False)
    MP = MaterialParametersFenics(K=2)

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

    return worm, MP, F0, CS


def time_simulation(solver, preconditioner):
    worm, MP, F0, CS = _setup()
    start_time = time.time()
    worm.solve(T, MP, F0.to_fenics(worm), CS.to_fenics(worm),
               solver_parameters={
                   'linear_solver': solver,
                   'preconditioner': preconditioner
               })
    sim_time = time.time() - start_time
    return sim_time


def plot_controls():
    import matplotlib.pyplot as plt
    from simple_worm.plot3d import plot_CS
    worm, MP, F0, CS = _setup()

    # Show the controls
    plot_CS(CS)
    plt.show()


def sweep_solvers():
    import matplotlib.pyplot as plt

    results = np.zeros((len(solvers), len(preconditioners)))
    results.fill(np.nan)

    for i, solver in enumerate(solvers):
        for j, preconditioner in enumerate(preconditioners):
            try:
                sim_time = time_simulation(solver, preconditioner)
                results[i, j] = sim_time
                print(f'Solver={solver}. Preconditioner={preconditioner}. Time taken: {timedelta(seconds=sim_time)}.')
            except Exception as e:
                print(f'Solver={solver}. Preconditioner={preconditioner}. Failed: {e}.')
                raise

    # Plot
    fig, axes = plt.subplots(1, figsize=(12, 12))
    ax = axes  # [0]
    ax.set_title(f'N={N}. T={T:.2f}. dt={dt:.3f}.')

    xs = np.arange(len(solvers))
    ax.set_xticks(xs)
    ax.set_xticklabels(solvers)
    ax.set_ylabel('Simulation time (s)')

    for j, preconditioner in enumerate(preconditioners):
        ax.scatter(x=xs + j / len(preconditioners) / 4, y=results[:, j], label=preconditioner, s=50, alpha=0.7)

    ax.legend()
    plt.show()


if __name__ == '__main__':
    sweep_solvers()
