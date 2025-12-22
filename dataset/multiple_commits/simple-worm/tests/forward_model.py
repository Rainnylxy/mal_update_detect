import numpy as np
from fenics import *

from simple_worm.controls import ControlsFenics, ControlsNumpy, ControlSequenceFenics, ControlSequenceNumpy
from simple_worm.frame import FrameFenics, FrameNumpy, FrameSequenceFenics
from simple_worm.util import v2f, f2n
from simple_worm.worm import Worm

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    # Needs importing here to line up with the imports in worm.py when both modules
    # are installed (even though not strictly required here).
    pass

# Parameters
N = 10
T = 0.4
dt = 0.1
n_timesteps = int(T / dt)


def _check_output(FS: FrameSequenceFenics, expect='same'):
    assert expect in ['same', 'different']
    n_timesteps = len(FS)
    for i in range(n_timesteps):
        for j in range(i + 1, n_timesteps):
            if expect == 'same':
                assert FS[i] == FS[j]
            elif expect == 'different':
                assert FS[i] != FS[j]


def _check_getters(worm: Worm):
    worm.get_x()
    worm.get_e1()
    worm.get_e2()


def test_defaults():
    print('\n\n----test_defaults')
    worm = Worm(N, dt)
    FS = worm.solve(T)
    _check_output(FS, expect='same')
    _check_getters(worm)


def test_solve_twice():
    print('\n\n----test_solve_twice')
    worm = Worm(N, dt)
    worm.solve(T)
    assert worm.t == T

    CS = ControlSequenceFenics(worm=worm, n_timesteps=n_timesteps)
    worm.solve(T, CS=CS, reset=False)
    assert np.allclose(worm.t, 2 * T)
    _check_getters(worm)


def test_stepwise_solve():
    print('\n\n----test_stepwise_solve')
    worm = Worm(N, dt)
    worm.initialise()
    print(f't={worm.t:.2f}')

    C_t1 = ControlsFenics(worm=worm)
    F_t1 = worm.update_solution(C_t1)
    print(f't={worm.t:.2f}')
    assert worm.t == dt

    C_t2 = ControlsFenics(worm=worm)
    F_t2 = worm.update_solution(C_t2)
    print(f't={worm.t:.2f}')
    assert worm.t == dt * 2

    FS = FrameSequenceFenics(
        frames=[F_t1, F_t2]
    )

    _check_output(FS, expect='same')
    _check_getters(worm)


def test_numpy_initial_frame():
    print('\n\n----test_numpy_initial_frame')
    worm = Worm(N, dt)

    # Set initial conditions manually
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    F0 = FrameNumpy(x=x0, worm=worm)

    # Must convert F0 to fenics before passing to solver
    FS = worm.solve(T, F0=F0.to_fenics(worm))
    _check_output(FS, expect='same')
    _check_getters(worm)


def test_expression_initial_frame():
    print('\n\n----test_expression_initial_frame')
    worm = Worm(N, dt)

    # Set initial conditions with fenics expressions
    # Online documentation missing but you can use simple functions like sin,
    # cos, etc. and variables with values passed as kwargs. For spatial
    # coordinate use x[0].
    x0 = v2f(Expression(('x[0]', '0', '0'), degree=1), fs=worm.V3)
    psi0 = v2f(Expression('0', degree=1), fs=worm.V)
    F0 = FrameFenics(x=x0, psi=psi0, worm=worm)

    F = worm.solve(T, F0=F0)
    _check_output(F, expect='same')
    _check_getters(worm)


def test_numpy_controls():
    print('\n\n----test_numpy_controls')
    worm = Worm(N, dt)

    # Create forcing functions (preferred curvatures) for each timestep
    C = ControlsNumpy(
        alpha=2 * np.ones(N),
        beta=3 * np.ones(N),
        gamma=5 * np.ones(N - 1),
    )
    CS = ControlSequenceNumpy(controls=C, n_timesteps=n_timesteps)

    FS = worm.solve(T, CS=CS.to_fenics(worm))
    _check_output(FS, expect='different')
    _check_getters(worm)


def test_expression_controls():
    print('\n\n----test_expression_controls')
    worm = Worm(N, dt)

    # Create forcing functions (preferred curvatures) using expressions
    # Online documentation missing but you can use simple functions like sin,
    # cos, etc. and variables with values passed as kwargs. For spatial
    # coordinate use x[0].
    C = ControlsFenics(
        alpha=v2f(Expression('v', degree=1, v=1), fs=worm.V),
        beta=v2f(Expression('v', degree=1, v=1), fs=worm.V),
        gamma=v2f(Expression('v', degree=0, v=1), fs=worm.Q),
    )
    CS = ControlSequenceFenics(controls=C, n_timesteps=n_timesteps)

    F = worm.solve(T, CS=CS)
    _check_output(F, expect='different')
    _check_getters(worm)


def test_projecting_outputs():
    print('\n\n----test_projecting_outputs')
    worm = Worm(N, dt)

    C = ControlsFenics(
        alpha=v2f(Expression('v', degree=1, v=1), fs=worm.V),
        beta=v2f(Expression('v', degree=1, v=1), fs=worm.V),
        gamma=v2f(Expression('v', degree=0, v=1), fs=worm.Q),
    )
    CS = ControlSequenceFenics(controls=C, n_timesteps=n_timesteps)

    FS1 = worm.solve(T, CS=CS, project_outputs=True)
    FS2 = worm.solve(T, CS=CS, project_outputs=False)

    for t in range(n_timesteps):
        assert not np.allclose(f2n(FS1[t].alpha), np.zeros(N))
        assert not np.allclose(f2n(FS1[t].beta), np.zeros(N))
        assert not np.allclose(f2n(FS1[t].gamma), np.zeros(N - 1))
        assert np.allclose(f2n(FS2[t].alpha), np.zeros(N))
        assert np.allclose(f2n(FS2[t].beta), np.zeros(N))
        assert np.allclose(f2n(FS2[t].gamma), np.zeros(N - 1))

    # Converting the frame sequences to numpy will calculate the outputs
    FS1n = FS1.to_numpy()
    FS2n = FS2.to_numpy()
    for t in range(n_timesteps):
        assert FS1n[t] == FS2n[t]


if __name__ == '__main__':
    test_defaults()
    test_solve_twice()
    test_stepwise_solve()
    test_numpy_initial_frame()
    test_expression_initial_frame()
    test_numpy_controls()
    test_expression_controls()
    test_projecting_outputs()
