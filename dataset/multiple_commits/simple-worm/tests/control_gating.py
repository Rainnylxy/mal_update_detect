import numpy as np
import pytest
from fenics import *

from simple_worm.control_gates import ControlGateNumpy, ControlGateFenics
from simple_worm.controls import ControlsFenics, ControlsNumpy, ControlSequenceFenics, ControlSequenceNumpy
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
N = 100
T = 0.4
dt = 0.1
n_timesteps = int(T / dt)

mesh = UnitIntervalMesh(N - 1)
P0 = FiniteElement('DP', mesh.ufl_cell(), 0)
P1 = FiniteElement('Lagrange', mesh.ufl_cell(), 1)
V = FunctionSpace(mesh, P1)
Q = FunctionSpace(mesh, P0)


def test_invalid_parameters():
    bad_params = [
        {'block': True, 'grad_up': 5},
        {'grad_up': 5},
        {'offset_up': 0.5},
        {'grad_down': 5},
        {'offset_down': 0.5},
        {'grad_up': -1, 'offset_up': 0.5},
        {'grad_down': -1, 'offset_down': 0.5},
        {'grad_up': 10, 'offset_up': -0.1},
        {'grad_up': 10, 'offset_up': 1.1},
        {'grad_down': 10, 'offset_down': -0.1},
        {'grad_down': 10, 'offset_down': 1.1},
    ]

    for params in bad_params:
        with pytest.raises(AssertionError):
            ControlGateNumpy(N=10, **params)
        with pytest.raises(AssertionError):
            ControlGateFenics(N=10, **params)


def test_fenics_to_numpy():
    CGf = ControlGateFenics(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    CGn = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    CGf2n = CGf.to_numpy()
    CGn2f = CGn.to_fenics()
    assert np.allclose(f2n(project(CGf.gate, V)), f2n(project(CGn2f.gate, V)), CGn.gate, CGf2n.gate)
    CGf = ControlGateFenics(N=N, block=True)
    CGn = ControlGateNumpy(N=N, block=True)
    CGf2n = CGf.to_numpy()
    CGn2f = CGn.to_fenics()
    assert np.allclose(f2n(project(CGf.gate, V)), f2n(project(CGn2f.gate, V)), CGn.gate, CGf2n.gate)


def test_fenics_gate_applies_to_controls():
    alpha_gate = ControlGateFenics(N=N, grad_up=10, offset_up=0.3, grad_down=10, offset_down=0.5)
    beta_gate = ControlGateFenics(N=N, grad_down=10, offset_down=0.5)
    gamma_gate = ControlGateFenics(N=N - 1, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    C = ControlsFenics(
        alpha=v2f(Expression('v', degree=1, v=1), fs=V),
        beta=v2f(Expression('v', degree=1, v=1), fs=V),
        gamma=v2f(Expression('v', degree=1, v=1), fs=Q),
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate,
    )
    assert np.allclose(f2n(project(C.get_alpha(), V)), f2n(project(alpha_gate.gate, V)))
    assert np.allclose(f2n(project(C.get_beta(), V)), f2n(project(beta_gate.gate, V)))
    assert np.allclose(f2n(project(C.get_gamma(), Q)), f2n(project(gamma_gate.gate, Q)))

    block_gate = ControlGateFenics(N=N, block=True)
    C = ControlsFenics(
        alpha=v2f(Expression('v', degree=1, v=1), fs=V),
        beta=v2f(Expression('v', degree=1, v=1), fs=V),
        gamma=v2f(Expression('v', degree=1, v=1), fs=Q),
        alpha_gate=block_gate,
    )
    assert np.allclose(f2n(project(C.get_alpha(), V)), f2n(project(block_gate.gate, V)))
    assert np.allclose(f2n(project(C.get_alpha(), V)), np.zeros(N))


def test_numpy_gate_applies_to_controls():
    alpha_gate = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    beta_gate = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    gamma_gate = ControlGateNumpy(N=N - 1, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    C = ControlsNumpy(
        alpha=np.ones(N),
        beta=np.ones(N),
        gamma=np.ones(N - 1),
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate,
    )
    assert np.allclose(C.get_alpha(), alpha_gate.gate)
    assert np.allclose(C.get_beta(), beta_gate.gate)
    assert np.allclose(C.get_gamma(), gamma_gate.gate)

    block_gate = ControlGateNumpy(N=N, block=True)
    C = ControlsNumpy(
        alpha=np.ones(N),
        beta=np.ones(N),
        gamma=np.ones(N - 1),
        alpha_gate=block_gate,
    )
    assert np.allclose(C.get_alpha(), block_gate.gate)
    assert np.allclose(C.get_alpha(), np.zeros(N))


def test_fenics_gate_applies_to_control_sequence():
    alpha_gate = ControlGateFenics(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    beta_gate = ControlGateFenics(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    gamma_gate = ControlGateFenics(N=N - 1, block=True)
    C = ControlsFenics(
        alpha=v2f(Expression('v', degree=1, v=1), fs=V),
        beta=v2f(Expression('v', degree=1, v=1), fs=V),
        gamma=v2f(Expression('v', degree=1, v=1), fs=Q)
    )
    CS = ControlSequenceFenics(
        controls=C,
        n_timesteps=n_timesteps,
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate
    )
    for C in CS:
        assert np.allclose(f2n(project(C.get_alpha(), V)), f2n(project(alpha_gate.gate, V)))
        assert np.allclose(f2n(project(C.get_beta(), V)), f2n(project(beta_gate.gate, V)))
        assert np.allclose(f2n(project(C.get_gamma(), Q)), f2n(project(gamma_gate.gate, Q)))


def test_numpy_gate_applies_to_control_sequence():
    alpha_gate = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    beta_gate = ControlGateNumpy(N=N, block=True)
    gamma_gate = ControlGateNumpy(N=N - 1, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    C = ControlsNumpy(
        alpha=np.ones(N),
        beta=np.ones(N),
        gamma=np.ones(N - 1),
    )
    CS = ControlSequenceNumpy(
        controls=C,
        n_timesteps=n_timesteps,
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate
    )
    for C in CS:
        assert np.allclose(C.get_alpha(), alpha_gate.gate)
        assert np.allclose(C.get_beta(), beta_gate.gate)
        assert np.allclose(C.get_gamma(), gamma_gate.gate)


def test_fenics_gated_controls():
    print('\n\n----test_fenics_gated_controls')
    worm = Worm(N, dt)

    C = ControlsFenics(
        alpha=v2f(Expression('v', degree=1, v=1), fs=worm.V),
        beta=v2f(Expression('v', degree=1, v=1), fs=worm.V),
        gamma=v2f(Expression('v', degree=0, v=1), fs=worm.Q),
    )

    CS_ungated = ControlSequenceFenics(
        controls=C,
        n_timesteps=n_timesteps
    )
    FS_ungated = worm.solve(T, CS=CS_ungated)

    alpha_gate = ControlGateFenics(N=N, block=True)
    beta_gate = ControlGateFenics(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    gamma_gate = ControlGateFenics(N=N - 1, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    CS_gated = ControlSequenceFenics(
        controls=C,
        n_timesteps=n_timesteps,
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate
    )
    FS_gated = worm.solve(T, CS=CS_gated)

    assert FS_ungated != FS_gated


def test_numpy_gated_controls():
    print('\n\n----test_numpy_gated_controls')
    worm = Worm(N, dt)

    C = ControlsNumpy(
        alpha=np.ones(N),
        beta=np.ones(N),
        gamma=np.ones(N - 1),
    )
    CS_ungated = ControlSequenceNumpy(
        controls=C,
        n_timesteps=n_timesteps
    )
    FS_ungated = worm.solve(T, CS=CS_ungated.to_fenics(worm))

    alpha_gate = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    beta_gate = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    gamma_gate = ControlGateNumpy(N=N - 1, block=True)
    CS_gated = ControlSequenceNumpy(
        controls=C,
        n_timesteps=n_timesteps,
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate
    )
    FS_gated = worm.solve(T, CS=CS_gated.to_fenics(worm))

    assert FS_ungated != FS_gated


def test_equality_checks():
    print('\n\n----test_equality_checks')
    worm = Worm(N, dt)
    C_ungated = ControlsNumpy(
        alpha=np.ones(N),
        beta=np.ones(N),
        gamma=np.ones(N - 1),
    )
    Cf_ungated = C_ungated.to_fenics(worm)
    alpha_gate = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    beta_gate = ControlGateNumpy(N=N, grad_down=10, offset_down=0.5)
    gamma_gate = ControlGateNumpy(N=N - 1, block=True)
    C_gated = ControlsNumpy(
        alpha=np.ones(N),
        beta=np.ones(N),
        gamma=np.ones(N - 1),
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate,
    )
    Cf_gated = C_gated.to_fenics(worm)

    assert C_ungated != C_gated
    assert Cf_ungated != Cf_gated

    assert np.allclose(alpha_gate.gate, f2n(project(Cf_gated.alpha_gate.gate, V)), atol=1e-3)
    assert np.allclose(beta_gate.gate, f2n(project(Cf_gated.beta_gate.gate, V)), atol=1e-3)
    assert np.allclose(gamma_gate.gate, f2n(project(Cf_gated.gamma_gate.gate, Q)), atol=1e-3)

    CS_ungated = ControlSequenceNumpy(
        controls=C_ungated,
        n_timesteps=n_timesteps
    )
    CS_gated = ControlSequenceNumpy(
        controls=C_gated,
        n_timesteps=n_timesteps,
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate
    )
    assert CS_ungated != CS_gated
    assert CS_ungated.to_fenics(worm) != CS_gated.to_fenics(worm)


def plot_gates():
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(3, figsize=(12, 12))

    ax_ups = axes[0]
    ax_ups.set_title('Control gates - ups')
    ax_downs = axes[1]
    ax_downs.set_title('Control gates - downs')
    ax_both = axes[2]
    ax_both.set_title('Control gates - combined')

    CG = ControlGateNumpy(N=N)
    ax_ups.plot(CG.gate, label='no args')
    CG = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5)
    ax_ups.plot(CG.gate, label='grad_up=10, offset_up=0.5')
    CG = ControlGateNumpy(N=N, grad_up=50, offset_up=0.2)
    ax_ups.plot(CG.gate, label='grad_up=50, offset_up=0.2')
    ax_ups.legend()

    CG = ControlGateNumpy(N=N, grad_down=10, offset_down=0.5)
    ax_downs.plot(CG.gate, label='grad_down=10, offset_down=0.5')
    CG = ControlGateNumpy(N=N, grad_down=50, offset_down=0.8)
    ax_downs.plot(CG.gate, label='grad_down=50, offset_down=0.8')
    ax_downs.legend()

    CG = ControlGateNumpy(N=N, grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5)
    ax_both.plot(CG.gate, label='grad_up=10, offset_up=0.5, grad_down=10, offset_down=0.5')
    CG = ControlGateNumpy(N=N, grad_up=50, offset_up=0.2, grad_down=50, offset_down=0.8)
    ax_both.plot(CG.gate, label='grad_up=50, offset_up=0.8, grad_down=50, offset_down=0.8')
    ax_both.legend()

    fig.tight_layout()
    plt.show()


def plot_CS_comparison():
    print('\n\n----plot_CS_comparison')
    import matplotlib.pyplot as plt
    from simple_worm.plot3d import plot_CS_vs_output, generate_interactive_scatter_clip, interactive
    interactive()
    T = 1
    dt = 0.01
    n_timesteps = int(T / dt)
    worm = Worm(N, dt)

    C = ControlsNumpy(
        alpha=np.ones(N) * 2 * np.pi,
        beta=np.ones(N) * 2 * np.pi,
        gamma=np.ones(N - 1) * 2 * np.pi,
    )
    CS_ungated = ControlSequenceNumpy(
        controls=C,
        n_timesteps=n_timesteps
    )
    FS_ungated = worm.solve(T, CS=CS_ungated.to_fenics(worm))
    plot_CS_vs_output(CS_ungated, FS_ungated.to_numpy(), show_ungated=True)
    plt.show()
    generate_interactive_scatter_clip(FS_ungated.to_numpy(), fps=20)

    alpha_gate = ControlGateNumpy(N=N, grad_up=100, offset_up=0.4, grad_down=100, offset_down=0.6)
    beta_gate = ControlGateNumpy(N=N, grad_down=100, offset_down=0.3)
    gamma_gate = ControlGateNumpy(N=N - 1, block=True)
    CS_gated = ControlSequenceNumpy(
        controls=C,
        n_timesteps=n_timesteps,
        alpha_gate=alpha_gate,
        beta_gate=beta_gate,
        gamma_gate=gamma_gate
    )
    FS_gated = worm.solve(T, CS=CS_gated.to_fenics(worm))
    plot_CS_vs_output(CS_gated, FS_gated.to_numpy(), show_ungated=True)
    plt.show()
    generate_interactive_scatter_clip(FS_gated.to_numpy(), fps=20)


if __name__ == '__main__':
    test_invalid_parameters()
    test_fenics_to_numpy()
    test_fenics_gate_applies_to_controls()
    test_numpy_gate_applies_to_controls()
    test_fenics_gate_applies_to_control_sequence()
    test_numpy_gate_applies_to_control_sequence()
    test_fenics_gated_controls()
    test_numpy_gated_controls()
    test_equality_checks()

    plot_gates()
    plot_CS_comparison()
