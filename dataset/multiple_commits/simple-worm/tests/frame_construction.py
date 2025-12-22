import numpy as np
import torch

from simple_worm.frame import FrameNumpy
from simple_worm.plot3d import plot_frame
from simple_worm.worm import Worm

N = 20
dt = 0.1
arrow_scale = 0.1


# Uncomment this line to show interactive plots (if supported on your machine)
# interactive()


def test_default_frame_construction():
    worm = Worm(N, dt)
    worm.initialise()
    plot_frame(worm, arrow_scale=arrow_scale)


def test_frame_from_straight_x0():
    worm = Worm(N, dt)

    # Create a numpy initial midline along x-axis
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    F0 = FrameNumpy(x=x0, worm=worm)

    worm.initialise(
        F0=F0.to_fenics(worm)
    )
    plot_frame(worm, arrow_scale=arrow_scale)


def test_frame_from_straight_x0_withtwist():
    worm = Worm(N, dt)

    # Create a numpy frame with an initial midline and twist
    x0 = np.zeros((3, N))
    x0[:][0] = np.linspace(1, 0, N, endpoint=True)
    psi = np.linspace(start=0, stop=np.pi, num=N)
    F0 = FrameNumpy(x=x0, psi=psi)

    worm.initialise(
        F0=F0.to_fenics(worm)
    )
    plot_frame(worm, arrow_scale=arrow_scale)


def test_frame_from_diag_x0_withtwist():
    worm = Worm(N, dt)

    # Midline pointing radially out to the unit sphere
    x0 = np.zeros((3, N))
    x0[0] = torch.linspace(start=0, end=1 / np.sqrt(3), steps=N)
    x0[1] = torch.linspace(start=0, end=1 / np.sqrt(3), steps=N)
    x0[2] = torch.linspace(start=1 / np.sqrt(3), end=0, steps=N)
    psi = np.linspace(start=0, stop=-np.pi, num=N)
    F0 = FrameNumpy(x=x0, psi=psi)

    worm.initialise(
        F0=F0.to_fenics(worm)
    )

    plot_frame(worm, arrow_scale=arrow_scale)


def test_frame_from_curved_x0_notwist():
    worm = Worm(N, dt)

    # Midline as a spiral
    x0 = np.zeros((3, N))
    x0[0] = np.sin(np.linspace(start=0, stop=2 * np.pi, num=N)) / 10
    x0[1] = np.cos(np.linspace(start=0, stop=2 * np.pi, num=N)) / 10
    x0[2] = torch.linspace(start=1 / np.sqrt(3), end=0, steps=N)
    F0 = FrameNumpy(x=x0, worm=worm)

    worm.initialise(
        F0=F0.to_fenics(worm)
    )

    plot_frame(worm, arrow_scale=arrow_scale)


def test_frame_from_curved_x0_with_twist():
    worm = Worm(N, dt)

    # Midline as a spiral
    x0 = np.zeros((3, N))
    x0[0] = np.sin(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[1] = np.cos(2 * np.pi * np.linspace(start=0, stop=1, num=N)) / 10
    x0[2] = torch.linspace(start=1 / np.sqrt(3), end=0, steps=N)
    psi = np.linspace(start=0, stop=-np.pi, num=N)
    F0 = FrameNumpy(x=x0, psi=psi)

    worm.initialise(
        F0=F0.to_fenics(worm)
    )

    plot_frame(worm, arrow_scale=arrow_scale)


if __name__ == '__main__':
    test_default_frame_construction()
    test_frame_from_straight_x0()
    test_frame_from_straight_x0_withtwist()
    test_frame_from_diag_x0_withtwist()
    test_frame_from_curved_x0_notwist()
    test_frame_from_curved_x0_with_twist()
