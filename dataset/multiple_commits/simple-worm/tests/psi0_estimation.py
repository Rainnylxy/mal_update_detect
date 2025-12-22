import numpy as np
import torch
from matplotlib import pyplot as plt

from simple_worm.frame import FrameNumpy, FrameFenics
from simple_worm.frame_torch import FrameTorch
from simple_worm.plot3d import cla, FrameArtist, interactive
from simple_worm.util import estimate_frame_components_from_x, v2f
from simple_worm.worm import Worm
from tests.helpers import psi_diff

N = 50
dt = 0.1
arrow_scale = 0.1

# Uncomment this line to show interactive plots (if supported on your machine)
# interactive()


def test_psi_estimation_consistency():
    worm = Worm(N, dt)

    # Create a numpy initial midline along x-axis
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    Fs = []

    # Fenics
    F0 = FrameFenics(x=v2f(x0, fs=worm.V3), worm=worm, estimate_psi=True)
    worm.initialise(F0=F0)
    Fs.append(worm.F.to_numpy())

    # Numpy
    F0 = FrameNumpy(x=x0, worm=worm, estimate_psi=True)
    worm.initialise(F0=F0.to_fenics(worm))
    Fs.append(worm.F.to_numpy())

    # Torch
    F0 = FrameTorch(x=torch.from_numpy(x0), worm=worm, estimate_psi=True)
    worm.initialise(F0=F0.to_fenics(worm))
    Fs.append(worm.F.to_numpy())

    for Fa in Fs:
        for Fb in Fs:
            assert (psi_diff(Fa, Fb) == 0).all()


def test_psi_estimation():
    worm = Worm(N, dt)
    window_size = 0.3

    def fix_range(F, ax):
        # Fix axes range
        mins, maxs = F.get_bounding_box()
        ax.set_xlim(mins[0], maxs[0])
        ax.set_ylim(mins[1], maxs[1])
        ax.set_zlim(mins[2], maxs[2])

    # Midline as a sine wave along e1 and e2
    x0 = np.zeros((3, N))
    x0[0] = 0.5 * np.sin(3 * 2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[1] = 2 * np.cos(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[2] = torch.linspace(start=0, end=0.5, steps=N)
    F0 = FrameNumpy(x=x0)
    worm.initialise(
        F0=F0.to_fenics(worm)
    )
    components = estimate_frame_components_from_x(x0, window_size=window_size)

    interactive()
    fig = plt.figure(figsize=(12, 5))
    F = worm.F.to_numpy()
    fa = FrameArtist(F, arrow_scale=arrow_scale)

    # Show default, no estimation
    ax = fig.add_subplot(1, 3, 1, projection='3d')
    cla(ax)
    fa.add_component_vectors(ax)
    fa.add_midline(ax)
    ax.set_title('Default (0-psi)')
    fix_range(F, ax)

    # Plot the component vectors as found from the sliding-window PCA
    ax = fig.add_subplot(1, 3, 2, projection='3d')
    cla(ax)
    fa.add_midline(ax)

    for i in range(N):
        cp = (F0.x[0, i], F0.x[1, i], F0.x[2, i])
        for j, pc in enumerate(components[i]):
            ax.plot(
                [cp[0], cp[0] + pc[0] / 10],
                [cp[1], cp[1] + pc[1] / 10],
                zs=[cp[2], cp[2] + pc[2] / 10],
                color=['red', 'blue', 'green'][j]
            )
    fix_range(F, ax)

    # Show with estimated psi
    F0 = FrameNumpy(x=x0, estimate_psi=True, estimate_psi_window_size=window_size)
    worm.initialise(
        F0=F0.to_fenics(worm)
    )
    F = worm.F.to_numpy()
    ax = fig.add_subplot(1, 3, 3, projection='3d')
    cla(ax)
    fa = FrameArtist(F, arrow_scale=arrow_scale)
    fa.add_component_vectors(ax)
    fa.add_midline(ax)
    fix_range(F, ax)

    fig.tight_layout()
    plt.show()


if __name__ == '__main__':
    test_psi_estimation_consistency()
    test_psi_estimation()
