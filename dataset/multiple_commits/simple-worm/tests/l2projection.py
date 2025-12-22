import numpy as np
import pytest
from fenics import *
from simple_worm.frame import FrameFenics
from simple_worm.worm import Worm

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    # Needs importing here to line up with the imports in worm.py when both modules
    # are installed (even though not strictly required here).
    pass

from simple_worm.util import lumped_projection, v2f, f2n

N = 20
T = 0.4
dt = 0.1
n_timesteps = int(T / dt)
show_plots = False


def test_l2projection():
    expr = Expression("sin(10*x[0])", degree=1)

    mesh = UnitIntervalMesh(50)
    space = FunctionSpace(mesh, "Lagrange", 1)

    proj = lumped_projection(expr, space)
    interp = Function(space)
    interp.interpolate(expr)

    d = assemble((proj - interp)**2 * dx)
    np.testing.assert_almost_equal(d, 0.0)


@pytest.mark.skip(reason='Frame is not normalised!')
def test_frame_vector():
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
        calculate_components=True,
        worm=worm
    )

    # Frame normalises the e1 and e2 vectors correctly
    assert np.allclose(np.linalg.norm(f2n(Ff.e1), axis=0), np.ones(N))
    assert np.allclose(np.linalg.norm(f2n(Ff.e2), axis=0), np.ones(N))


def test_normalisation():
    # https://fenicsproject.discourse.group/t/normalising-vectors-gives-poor-results/6191

    # Set up the mesh and elements
    N = 20
    mesh = UnitIntervalMesh(N - 1)
    P1 = FiniteElement('Lagrange', mesh.ufl_cell(), 1)
    P1_3 = MixedElement([P1] * 3)

    # V3 is the function space containing a 3D vector (e0) at each vertex of the mesh
    V3 = FunctionSpace(mesh, P1_3)
    e0 = Function(V3)

    def _dof_maps(fs: FunctionSpace) -> np.ndarray:
        """Returns a numpy array for the dof maps of the function space"""
        n_sub = fs.num_sub_spaces()
        if n_sub > 0:
            dof_map = np.array([_dof_maps(fs.sub(d)) for d in range(n_sub)])
        else:
            dof_map = np.array(fs.dofmap().dofs())

        return dof_map

    def fenics_to_numpy(var: Function) -> np.ndarray:
        """Returns a numpy array containing fenics function values"""
        fs = var.function_space()
        dof_maps = _dof_maps(fs)
        vec = var.vector().get_local()
        arr = np.zeros_like(dof_maps, dtype=np.float64)
        for i in np.ndindex(dof_maps.shape):
            arr[i] = vec[dof_maps[i]]

        return arr

    # Initialise the e0 vectors at random
    values = np.random.randn(3, N)
    dof_maps = _dof_maps(V3)
    vec = e0.vector()
    for i in np.ndindex(dof_maps.shape):
        vec[dof_maps[i]] = values[i]

    # Verify that the values are set correctly
    e0_numpy = fenics_to_numpy(e0)
    assert np.allclose(values, e0_numpy)

    # Try to normalise the e0 vectors

    # Method A:
    e0_normalised = e0 / sqrt(dot(e0, e0))
    e0_normalised_numpy = fenics_to_numpy(project(e0_normalised, V3))
    e0_norms = np.linalg.norm(e0_normalised_numpy, axis=0)
    assert not np.allclose(e0_norms, np.ones_like(e0_norms))  # Fails, quite badly

    # Check error in vector magnitude using L2 norm:
    err = sqrt(dot(e0_normalised, e0_normalised)) - 1.0
    L2_err_norm = sqrt(assemble(err * err * dx))
    assert near(L2_err_norm, 0.0)  # But the norms are ok

    # Try to interpolate e0_normalised to get values out
    e0_normalised = project(e0_normalised, V3)  # put this line in to allow compilation
    expr = Expression(
        ["v[0]", "v[1]", "v[2]"],
        v=e0_normalised,
        degree=1,
    )
    e0_interp = interpolate(expr, V3)
    e0_n = fenics_to_numpy(e0_interp)
    e0_norms = np.linalg.norm(e0_n, axis=0)
    assert not np.allclose(e0_norms, np.ones_like(e0_norms))  # Fails again

    # Method B:
    e0_norm = Expression('sqrt(v[0]*v[0]+v[1]*v[1]+v[2]*v[2])', v=e0, degree=1)
    e0_normalised = Expression(('e[0]/n', 'e[1]/n', 'e[2]/n'), e=e0, n=e0_norm, degree=1)
    e0_normalised = interpolate(e0_normalised, V3)
    e0_normalised_numpy = fenics_to_numpy(e0_normalised)
    e0_norms = np.linalg.norm(e0_normalised_numpy, axis=0)
    assert np.allclose(e0_norms, np.ones_like(e0_norms))  # Succeeds, but doesn't work for adjoint/inverse problems

    # Check error in functional norm (using evaluations at quadrature points:
    err = sqrt(dot(e0_normalised, e0_normalised)) - 1.0
    L2_err_norm = sqrt(assemble(err * err * dx))
    assert not near(L2_err_norm, 0.0)  # Fails


if __name__ == "__main__":
    test_l2projection()
    test_frame_vector()
    test_normalisation()
