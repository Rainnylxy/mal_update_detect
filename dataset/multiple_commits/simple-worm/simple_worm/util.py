from typing import List, Union

import numpy as np
from fenics import *
from ufl.core.expr import Expr
from ufl.tensors import ListTensor

from simple_worm.material_parameters import MP_DEFAULT_K

PSI_ESTIMATE_WS_DEFAULT = 0.3

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    pass
    # This optional import is only needed if derivatives are being taken.


def f2n(var: Union[Function, List[Function], ListTensor]) -> np.ndarray:
    """
    Fenics to Numpy
    Returns a numpy array containing fenics function values
    """
    if type(var) == list:
        return np.stack([f2n(v) for v in var])
    elif type(var) == ListTensor:
        return np.stack([f2n(project(v)) for v in var])

    fs = var.function_space()
    dof_maps = _dof_maps(fs)
    vec = var.vector().get_local()
    arr = np.zeros_like(dof_maps, dtype=np.float64)
    for i in np.ndindex(dof_maps.shape):
        arr[i] = vec[dof_maps[i]]

    return arr


def v2f(
        val: Union[np.ndarray, Expression, Function],
        var: Function = None,
        fs: FunctionSpace = None,
        name: str = None
) -> Function:
    """
    Value (mixed) to Fenics
    Set a value to a new or existing fenics variable.
    """
    assert var is not None or fs is not None
    if var is None:
        var = Function(fs, name=name)

    # If numpy array passed, set these as the function values
    if isinstance(val, np.ndarray):
        _set_vals_from_numpy(var, val)

    # If an expression is passed, interpolate on the space
    elif isinstance(val, Expr):
        var.assign(interpolate(val, var.function_space()))

    # If a function is passed, just assign
    elif isinstance(val, Function):
        var.assign(val)

    # otherwise raise an error
    else:
        raise RuntimeError("Unknown value type to convert")

    return var


def _set_vals_from_numpy(var: Function, values: np.ndarray):
    """
    Sets the vertex-values (or between-vertex-values) of a variable from a numpy array
    """
    fs = var.function_space()
    dof_maps = _dof_maps(fs)
    assert values.shape == dof_maps.shape, f'shapes don\'t match!  values: {values.shape}. dof_maps: {dof_maps.shape}'
    vec = var.vector()
    for i in np.ndindex(dof_maps.shape):
        vec[dof_maps[i]] = values[i]


def _dof_maps(fs: FunctionSpace) -> np.ndarray:
    """
    Returns a numpy array for the dof maps of the function space
    """
    n_sub = fs.num_sub_spaces()
    if n_sub > 0:
        dof_map = np.array([_dof_maps(fs.sub(d)) for d in range(n_sub)])
    else:
        dof_map = np.array(fs.dofmap().dofs())

    return dof_map


def expand_numpy(v: np.ndarray, size=1) -> np.ndarray:
    """
    Expand a numpy array along a new dimension prepended to the front.
    """
    v = np.expand_dims(v, axis=0)
    if size > 1:
        v = np.repeat(v, repeats=size, axis=0)
    return v


def estimate_frame_components_from_x(x: np.ndarray, window_size: float = PSI_ESTIMATE_WS_DEFAULT) -> np.ndarray:
    """
    Estimate the frame components (e0,e1,e2) at each point along the body using PCA in a sliding window.
    The `window_size` argument is the proportion of the body points to use for the window.
    """
    from sklearn.decomposition import PCA
    assert 0 < window_size < 1, 'The window size must be greater than 0 and less than 1.'

    # Calculate a reference frame using the whole body
    pca = PCA()
    pca.fit(x.T)
    components_ref = pca.components_

    # Find a component frame at each point using PCA over a sliding window
    components = []
    N = x.shape[-1]
    for i in range(N):
        window_start = max(0, int(i - (N * window_size) / 2))
        window_end = min(N - 1, int(i + (N * window_size) / 2))

        # Ensure the window has at least 3 points
        if window_start + window_end < 2:
            if window_start == 0:
                window_end = window_start + 2
            elif window_end == N - 1:
                window_start = window_end - 2
            else:
                window_start = window_start - 1
                window_end = window_end - 1

        pts = x[:, window_start:window_end + 1].T
        pca = PCA()
        pca.fit(pts)
        components_i = pca.components_

        # Correlate components with reference window to correct for sign-flips
        for j in range(3):
            if np.dot(components_i[j], components_ref[j]) < 0:
                components_i[j] *= -1
        components.append(components_i)
    components = np.array(components)

    return components


def calculate_psi_from_components(components: np.ndarray) -> np.ndarray:
    """
    Calculate the rotation angle psi of e1/e2 around e0.
    """

    # Normalise components
    components = components / np.linalg.norm(components, axis=2)[:, :, np.newaxis]
    e0 = components[:, 0].T
    e1 = components[:, 1].T

    # Convert e0 to spherical coordinates to find theta/phi
    e0_x, e0_y, e0_z = e0[0], e0[1], e0[2]
    theta0 = np.arccos(e0_z)
    phi0 = np.arctan2(e0_y, e0_x)

    # 0-psi corresponds to e1 as the derivative of e0 wrt theta
    e1_ref = np.array([
        np.cos(theta0) * np.cos(phi0),
        np.cos(theta0) * np.sin(phi0),
        -np.sin(theta0)
    ])

    # psi is the angle between the computed e1 and e1_ref
    e1_dot_e1_ref = np.einsum('in,in->n', e1, e1_ref)
    e1_ref_cross_e1 = np.cross(e1_ref, e1, axis=0)
    e1_ref_cross_e1_dot_e0 = np.einsum('ij,ij->j', e1_ref_cross_e1, e0)

    psi = np.arctan2(e1_ref_cross_e1_dot_e0, e1_dot_e1_ref)

    return psi


def estimate_psi_from_x(x: np.ndarray, window_size: float = PSI_ESTIMATE_WS_DEFAULT) -> np.ndarray:
    """
    Estimate the twist angle psi along the body from the midline.
    """
    components = estimate_frame_components_from_x(x, window_size)
    psi = calculate_psi_from_components(components)
    return psi


def lumped_projection(expr, space):
    """
    Computes the lumped l2 projection of expr onto space
    """

    # lumped quadrature rule
    dxL = dx(scheme='vertex', degree=1,
             metadata={'representation': 'quadrature',
                       'degree': 1})

    # set up problem
    u = TrialFunction(space)
    v = TestFunction(space)

    a = inner(u, v) * dxL
    b = inner(expr, v) * dxL

    # solve
    ret = Function(space)
    solve(a == b, ret)

    return ret


def estimate_K_from_x(FS: 'FrameSequenceNumpy', K0: float = MP_DEFAULT_K, verbosity: int = 1) -> float:
    """
    Estimate the K parameter from data.
    """
    from scipy.optimize import least_squares

    assert verbosity in [0, 1, 2], 'verbosity must be in (0,1,2). Refer to scipy.optimize.least_squares for details.'

    # Tangent (tau) = e0
    if np.allclose(FS.e0, np.zeros_like(FS.e0)):
        raise RuntimeError('e0 is all zeros, ensure components are calculated before trying to estimate K!')
    tau = FS.e0
    tautau = np.einsum('tin,tjn->tijn', tau, tau)

    # Sanity check:
    # assert np.allclose(
    #     np.outer(tau[0, :, 0], tau[0, :, 0]),
    #     tautau[0, :, :, 0]
    # )

    # Length element mu = |x_u|
    mu = np.linalg.norm(np.gradient(FS.x, axis=2), axis=1)

    # Time derivative of midline
    xt = np.gradient(FS.x, axis=0)

    # Static phi basis
    phis = np.array([[1, 0, 0], [0, 1, 0], [0, 0, 1]])

    def func(K_):
        t1 = (tautau + K_[0] * (np.eye(3)[None, ..., None] - tautau))  # 4.2
        t2 = np.einsum('tijn,tin->tjn', t1, xt)
        t3 = np.einsum('tin,ip->ptn', t2, phis)
        t4 = t3 * mu
        residuals = t4.sum(axis=-1).flatten()
        return residuals

    K_est = least_squares(
        func,
        x0=K0,
        jac='3-point',
        bounds=(0, np.inf),
        method='trf',
        tr_solver='exact',
        verbose=verbosity
    )

    return float(K_est.x[0])
