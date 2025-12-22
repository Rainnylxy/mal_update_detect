import sys

import numpy as np

from simple_worm.controls import ControlsNumpy, ControlSequenceNumpy
from simple_worm.frame import FrameNumpy, FrameFenics, FrameSequenceNumpy
from simple_worm.util import v2f
from simple_worm.worm import Worm

sys.path.append('.')
from tests.helpers import psi_diff

N = 20
T = 0.4
dt = 0.1
n_timesteps = int(T / dt)
show_plots = False


def _test_closeness(Ff, Fn, atol):
    assert (psi_diff(Ff, Fn) < atol).all()
    assert np.allclose(Ff.x, Fn.x)
    assert np.allclose(Ff.e0, Fn.e0, atol=atol)
    assert np.allclose(Ff.e1, Fn.e1, atol=atol)
    assert np.allclose(Ff.e2, Fn.e2, atol=atol)

    for v in ['x', 'psi', 'e0', 'e1', 'e2']:
        if v == 'psi':
            max_err = np.max(psi_diff)
        else:
            max_err = np.abs(getattr(Ff, v) - getattr(Fn, v)).max()
        print(f'max error in {v}: {max_err}')


def _plot_component_comparison(Ff, Fn, title=None):
    if not show_plots:
        return
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(3, 3, sharex=True, figsize=(12, 12))
    for i in range(3):
        for j in range(3):
            ax = axes[i, j]
            ax.set_title(f'e{i}_{j}')
            ax.plot(getattr(Ff, f'e{i}')[j], label='fenics')
            ax.plot(getattr(Fn, f'e{i}')[j], label='numpy')
            ax.legend()
    if title is not None:
        fig.suptitle(title)
    plt.show()


def test_cc_from_straight_x0():
    print('\n--- test_cc_from_straight_x0')
    worm = Worm(N, dt)

    # Create a numpy initial midline along x-axis with no twist
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    psi = np.zeros(N)

    # Create the frames
    Ff = FrameFenics(
        x=v2f(x0, fs=worm.V3, name='x'),
        psi=v2f(psi, fs=worm.V, name='psi'),
        worm=worm,
        calculate_components=True
    )
    Ff = Ff.to_numpy()
    Fn = FrameNumpy(x=x0, calculate_components=True)

    _plot_component_comparison(Ff, Fn, title='cc_from_straight_x0')
    _test_closeness(Ff, Fn, atol=1e-14)


def test_cc_from_straight_x0_withtwist():
    print('\n--- test_cc_from_straight_x0_withtwist')
    worm = Worm(N, dt)

    # Create a numpy initial midline along x-axis with twist
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    psi = np.linspace(start=np.pi - 0.1, stop=np.pi + 0.1, num=N)

    # Create the frames
    Ff = FrameFenics(
        x=v2f(x0, fs=worm.V3, name='x'),
        psi=v2f(psi, fs=worm.V, name='psi'),
        worm=worm,
        calculate_components=True
    )
    Ff = Ff.to_numpy()
    Fn = FrameNumpy(x=x0, psi=psi, calculate_components=True)

    _plot_component_comparison(Ff, Fn, title='cc_from_straight_x0_withtwist')
    _test_closeness(Ff, Fn, atol=1e-7)


def test_cc_from_diag_x0_withtwist():
    print('\n--- test_cc_from_diag_x0_withtwist')
    worm = Worm(N, dt)

    # Midline pointing radially out to the unit sphere
    x0 = np.zeros((3, N))
    x0[0] = np.linspace(start=0, stop=1 / np.sqrt(3), num=N)
    x0[1] = np.linspace(start=0, stop=1 / np.sqrt(3), num=N)
    x0[2] = np.linspace(start=1 / np.sqrt(3), stop=0, num=N)
    psi = np.linspace(start=0, stop=-np.pi, num=N)

    # Create the frames
    Ff = FrameFenics(
        x=v2f(x0, fs=worm.V3, name='x'),
        psi=v2f(psi, fs=worm.V, name='psi'),
        worm=worm,
        calculate_components=True
    )
    Ff = Ff.to_numpy()
    Fn = FrameNumpy(x=x0, psi=psi, calculate_components=True)

    _plot_component_comparison(Ff, Fn, title='cc_from_diag_x0_withtwist')
    _test_closeness(Ff, Fn, atol=2e-3)


def test_cc_from_spiral_x0_withtwist():
    print('\n--- test_cc_from_spiral_x0_withtwist')
    worm = Worm(N, dt)

    # Midline as a spiral
    x0 = np.zeros((3, N))
    x0[0] = np.sin(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[1] = np.cos(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[2] = np.linspace(start=1 / np.sqrt(3), stop=0, num=N)
    psi = np.linspace(start=0, stop=-np.pi, num=N)

    # Create the frames
    Ff = FrameFenics(
        x=v2f(x0, fs=worm.V3, name='x'),
        psi=v2f(psi, fs=worm.V, name='psi'),
        worm=worm,
        calculate_components=True
    )
    Ff = Ff.to_numpy()
    Fn = FrameNumpy(x=x0, psi=psi, calculate_components=True)

    _plot_component_comparison(Ff, Fn, title='cc_from_spiral_x0_withtwist')
    _test_closeness(Ff, Fn, atol=1e-1)


def test_cc_frame_sequence():
    print('\n--- test_cc_frame_sequence')
    worm = Worm(N, dt)

    # Midline as a spiral
    x0 = np.zeros((3, N))
    x0[0] = np.sin(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[1] = np.cos(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[2] = np.linspace(start=1 / np.sqrt(3), stop=0, num=N)
    psi = np.linspace(start=0, stop=-np.pi, num=N)

    F0 = FrameFenics(
        x=v2f(x0, fs=worm.V3, name='x'),
        psi=v2f(psi, fs=worm.V, name='psi'),
        worm=worm,
        calculate_components=True
    )

    # Create forcing functions (preferred curvatures) for each timestep
    C = ControlsNumpy(
        alpha=2 * np.ones(N),
        beta=3 * np.ones(N),
        gamma=5 * np.ones(N - 1),
    )
    CS = ControlSequenceNumpy(controls=C, n_timesteps=n_timesteps)

    # Run the model forwards to get the output frame sequence
    FSf = worm.solve(T, F0=F0, CS=CS.to_fenics(worm))
    FSfn = FSf.to_numpy()

    # Create a new numpy FS using only x and psi
    FSn = FrameSequenceNumpy(x=FSfn.x, psi=FSfn.psi, calculate_components=True)

    if show_plots:
        for t, Ff in enumerate(FSfn):
            Fn = FSn[t]
            fig, ax = plt.subplots(1)
            ax.plot(Fn.psi)
            ax.set_title(f'cc_frame_sequence psi frame={t}')
            plt.show()
            _plot_component_comparison(Ff, Fn, title=f'cc_frame_sequence frame={t}')

    _test_closeness(FSfn, FSn, atol=0.15)


if __name__ == '__main__':
    test_cc_from_straight_x0()
    test_cc_from_straight_x0_withtwist()
    test_cc_from_diag_x0_withtwist()
    test_cc_from_spiral_x0_withtwist()
    test_cc_frame_sequence()
