import time

from fenics import *

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    # Needs importing here to line up with the imports in worm.py when both modules
    # are installed (even though not strictly required here).
    pass

from simple_worm.controls import ControlsFenics
from simple_worm.util import v2f
from simple_worm.worm import Worm

# Parameters
N = 32
T = 5
dt = 5.0e-2
n_timesteps = int(T / dt)


def test_constant_controls():
    worm = Worm(N, dt)
    worm.initialise()
    F = worm.F

    my_alpha = Expression("2.0*sin(3*pi*x[0]/2)", degree=1)
    my_beta = Expression("3.0*cos(3*pi*x[0]/2)", degree=1)
    my_gamma = Expression("5.0*cos(2*pi*x[0])", degree=0)

    C = ControlsFenics(
        alpha=v2f(my_alpha, fs=worm.V),
        beta=v2f(my_beta, fs=worm.V),
        gamma=v2f(my_gamma, fs=worm.Q),
    )

    while worm.t < T:
        F = worm.update_solution(C, solver_parameters={"linear_solver": "lu"}, project_outputs=True)

    e_alpha = assemble((F.alpha - my_alpha)**2 * dx())
    e_beta = assemble((F.beta - my_beta)**2 * dx())
    e_gamma = assemble((F.gamma - my_gamma)**2 * dx())

    tol = 1.0e-5  # TODO relate this tolerance to linear solver tolerance
    assert e_alpha < tol
    assert e_beta < tol
    assert e_gamma < tol


def test_projections():
    worm = Worm(N, dt)
    worm.initialise

    for degree in [1, 2, 4, 8, 16, 32]:
        print(f"degree = {degree}")
        my_alpha = Expression("2.0*sin(3*pi*x[0]/2)", degree=degree)
        iter = 1000

        tic = time.perf_counter()
        for i in range(iter):
            alpha = v2f(my_alpha, fs=worm.V)
        toc = time.perf_counter()

        print(f"{(toc - tic) / iter:0.4f}: f2n")

        tic = time.perf_counter()
        for i in range(iter):
            alpha = project(my_alpha, worm.V)
        toc = time.perf_counter()

        print(f"{(toc - tic) / iter:0.4f}: project")

        from simple_worm.util import lumped_projection

        tic = time.perf_counter()
        for i in range(iter):
            alpha = lumped_projection(my_alpha, worm.V)
        toc = time.perf_counter()

        print(f"{(toc - tic) / iter:0.4f}: lumped_projection")

        tic = time.perf_counter()
        u = TrialFunction(worm.V)
        v = TestFunction(worm.V)
        f = Constant(0)
        a = inner(u, v) * dx
        b = inner(f, v) * dx
        alpha = Function(worm.V)
        for i in range(iter):
            f = my_alpha
            solve(a == b, alpha)
        toc = time.perf_counter()
        print(f"{(toc - tic) / iter:0.4f}: project cached")


if __name__ == "__main__":
    test_constant_controls()
    # test_projections()
