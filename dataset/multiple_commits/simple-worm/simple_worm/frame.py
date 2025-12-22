from abc import ABC, abstractmethod
from typing import Tuple, List, Optional, Union

import numpy as np
from fenics import *
from ufl import atan_2
from ufl.core.expr import Expr

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass

from simple_worm.util import v2f, f2n, estimate_psi_from_x, PSI_ESTIMATE_WS_DEFAULT

FRAME_KEYS = ['x', 'psi', 'e0', 'e1', 'e2', 'alpha', 'beta', 'gamma']
FRAME_COMPONENT_KEYS = ['e0', 'e1', 'e2']


def grad(function): return Dx(function, 0)


class Frame(ABC):
    """
    The Frame class stores the position/midline coordinates of the worm body (x) along with
    an orthonormal frame (e0/e1/e2) defined at each coordinate. The first frame component (e0)
    points in the direction of the midline and therefore can be derived directly from it.
    This leaves just a single degree of freedom required to define e1 and e2. This is the
    rotation angle of e1/e2 around e0 (psi). Psi can be left empty and will default to 0 everywhere
    or can be estimated using a sliding-window PCA approach if `estimate_psi` is set to True.
    """

    def __init__(
            self,
            x=None,
            psi=None,
            e0=None,
            e1=None,
            e2=None,
            alpha=None,
            beta=None,
            gamma=None,
            worm: 'Worm' = None,
            estimate_psi: bool = False,
            estimate_psi_window_size: float = PSI_ESTIMATE_WS_DEFAULT
    ):
        # Must have all components or none of them
        assert all(e is None for e in [e0, e1, e2]) \
               or all(e is not None for e in [e0, e1, e2])

        # Position/midline
        if x is None:
            assert worm is not None
            x = self._init_x(worm)
        self.x = x

        # Rotation
        if psi is None:
            psi = self._init_psi(worm, estimate_psi, estimate_psi_window_size)
        self.psi = psi

        # Frame component vectors
        if e0 is None:
            e0, e1, e2 = self._init_components()
        self.e0 = e0
        self.e1 = e1
        self.e2 = e2

        # Curvature and twist
        if alpha is None:
            alpha, beta, gamma = self._init_curvature_and_twist(worm)
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

    @abstractmethod
    def clone(self) -> 'Frame':
        pass

    @abstractmethod
    def _init_x(self, worm: 'Worm'):
        pass

    @abstractmethod
    def _init_psi(self, worm: 'Worm' = None, estimate: bool = False, window_size: float = PSI_ESTIMATE_WS_DEFAULT):
        pass

    @abstractmethod
    def _init_components(self) -> Tuple:
        pass

    @abstractmethod
    def _init_curvature_and_twist(self, worm: 'Worm' = None) -> Tuple:
        pass

    @abstractmethod
    def __eq__(self, other: 'Frame') -> bool:
        pass


class FrameFenics(Frame):
    def __init__(
            self,
            x: Function = None,
            psi: Function = None,
            e0: Function = None,
            e1: Function = None,
            e2: Function = None,
            alpha: Function = None,
            beta: Function = None,
            gamma: Function = None,
            kappa_expr: Expr = None,
            gamma_expr: Expr = None,
            gamma_res: float = 0,
            worm: 'Worm' = None,
            estimate_psi: bool = False,
            estimate_psi_window_size: float = PSI_ESTIMATE_WS_DEFAULT,
            calculate_components: bool = False
    ):
        assert worm is not None
        self.worm = worm

        # Get function spaces
        self.V3 = self.worm.V3
        self.V = self.worm.V
        self.Q = self.worm.Q

        super().__init__(x, psi, e0, e1, e2, alpha, beta, gamma, worm, estimate_psi, estimate_psi_window_size)

        # Expressions for the curvature and twist
        self.kappa_expr = kappa_expr
        self.gamma_expr = gamma_expr

        # Difference between gamma as output from model and as recalculated from the curvature.
        self.gamma_res = gamma_res

        # Calculate the frame components from x and psi
        if calculate_components:
            self.calculate_components()

    def clone(self) -> 'FrameFenics':
        return FrameFenics(
            x=self.x.copy(deepcopy=True),
            psi=self.psi.copy(deepcopy=True),
            e0=self.e0.copy(deepcopy=True),
            e1=self.e1.copy(deepcopy=True),
            e2=self.e2.copy(deepcopy=True),
            alpha=self.alpha.copy(deepcopy=True),
            beta=self.beta.copy(deepcopy=True),
            gamma=self.gamma.copy(deepcopy=True),
            kappa_expr=self.kappa_expr,
            gamma_expr=self.gamma_expr,
            gamma_res=self.gamma_res,
            worm=self.worm
        )

    def _init_x(self, worm: 'Worm') -> Function:
        x = v2f(val=worm.x0_default, fs=worm.V3, name='x')
        return x

    def _init_psi(self, worm: 'Worm' = None, estimate: bool = False, window_size: float = PSI_ESTIMATE_WS_DEFAULT) \
            -> Function:
        assert worm is not None
        if estimate:
            psi = estimate_psi_from_x(f2n(self.x), window_size)
            psi = v2f(val=psi, fs=worm.V, name='psi')
        else:
            psi = v2f(val=worm.psi0_default, fs=worm.V, name='psi')
        return psi

    def _init_components(self) -> Tuple[Function, Function, Function]:
        e0 = Function(self.V3)
        e1 = Function(self.V3)
        e2 = Function(self.V3)
        return e0, e1, e2

    def _init_curvature_and_twist(self, worm: 'Worm' = None) -> Tuple[Function, Function, Function]:
        alpha = Function(self.V)
        beta = Function(self.V)
        gamma = Function(self.Q)
        return alpha, beta, gamma

    def calculate_components(self):
        """
        Calculate the e0/e1/e2 orthonormal frame components from the midline x and the rotation angle psi.
        """

        # e0 - normal to cross section; points along the body
        mu = sqrt(inner(grad(self.x), grad(self.x)))
        tau = grad(self.x) / mu
        e0 = self._project_and_normalise(tau)
        self.e0.assign(e0)

        # Convert e0 to spherical coordinates to find theta/phi
        e0_x, e0_y, e0_z = e0.split()
        theta0 = acos(e0_z)
        phi0 = atan_2(e0_y, e0_x)

        # Let e1 be the derivative of e0 wrt theta
        e1 = as_vector([
            cos(theta0) * cos(phi0),
            cos(theta0) * sin(phi0),
            -sin(theta0)
        ])

        # Then apply the rotation of e1 around e0 by psi
        e1 = e1 * cos(self.psi) \
             + cross(e0, e1) * sin(self.psi) \
             + e0 * dot(e0, e1) * (1 - cos(self.psi))
        e1 = self._project_and_normalise(e1)
        self.e1.assign(e1)

        # e2 is found by cross product
        e2 = cross(self.e0, self.e1)
        e2 = self._project_and_normalise(e2)
        self.e2.assign(e2)

    def _project_and_normalise(self, v: Expr) -> Function:
        """
        Project the variable/tensor/expression to V3 and normalise.
        """
        # TODO do we actually want this project?
        v = project(v / sqrt(dot(v, v)), self.V3)
        return v

    def to_numpy(self) -> 'FrameNumpy':
        self.project_outputs()
        args = {k: f2n(getattr(self, k)) for k in FRAME_KEYS}
        return FrameNumpy(**args)

    def update(self, x: Function, varphi: Expr, kappa_expr: Expr, gamma_expr: Expr):
        # Update position
        self.x.assign(project(x, self.V3))

        # Last e0
        tauv = self.e0

        # Update frame
        new_tauv = self._project_and_normalise(grad(x))
        self.e0.assign(new_tauv)

        # Update e1, e2
        def rotated_frame(v):
            k = cross(tauv, new_tauv)
            c = dot(tauv, new_tauv)
            tmp = v * c \
                  + cross(k, v) \
                  + dot(v, k) / (1 + c) * k
            ret = tmp * cos(varphi) \
                  + cross(new_tauv, tmp) * sin(varphi) \
                  + dot(tmp, new_tauv) * (1 - cos(varphi)) * new_tauv
            return ret

        # Rotate frame around e0
        e1 = rotated_frame(self.e1)

        # Orthogonalise e1 against e0
        e1 = e1 - dot(e1, self.e0) / dot(self.e0, self.e0) * self.e0
        e1 = self._project_and_normalise(e1)
        self.e1.assign(e1)

        # e2 is found by cross product
        e2 = cross(self.e0, e1)
        e2 = self._project_and_normalise(e2)
        self.e2.assign(e2)

        # Update curvature and twist
        self.kappa_expr = kappa_expr
        self.gamma_expr = gamma_expr

        # Calculate gamma residual
        mu = sqrt(dot(grad(self.x), grad(self.x)))
        res = assemble(((self.gamma_expr - dot(grad(self.e1), self.e2)) / mu)**2 * dx)
        self.gamma_res = res

    def project_outputs(self):
        """
        Project the curvature onto the e1 and e2 directions to give outputs alpha and beta.
        Project the twist expression to give gamma.
        Calculate the rotation angle psi.
        """

        # Project curvature and twist
        if self.kappa_expr is not None:
            project(dot(self.kappa_expr, self.e1), self.V, function=self.alpha)
            project(dot(self.kappa_expr, self.e2), self.V, function=self.beta)
        if self.gamma_expr is not None:
            project(self.gamma_expr, self.Q, function=self.gamma)

        # Update psi
        self._update_psi()

    def _update_psi(self):
        # Convert e0 to spherical coordinates to find theta/phi
        theta0 = Expression('acos(e[2])', e=self.e0, degree=1)
        phi0 = Expression('atan2(e[1], e[0])', e=self.e0, degree=1)

        # 0-psi corresponds to e1 as the derivative of e0 wrt theta
        e1_ref = Expression((
            'cos(t) * cos(p)',
            'cos(t) * sin(p)',
            '-sin(t)',
        ), t=theta0, p=phi0, degree=1)

        # psi is the angle between the computed e1 and e1_ref
        e1_dot_e1_ref = Expression('a[0]*b[0]+a[1]*b[1]+a[2]*b[2]', a=self.e1, b=e1_ref, degree=1)
        e1_ref_cross_e1 = Expression((
            'a[1]*b[2]-a[2]*b[1]',
            'a[2]*b[0]-a[0]*b[2]',
            'a[0]*b[1]-a[1]*b[0]',
        ), a=e1_ref, b=self.e1, degree=1)
        e1_ref_cross_e1_dot_e0 = Expression('a[0]*b[0]+a[1]*b[1]+a[2]*b[2]', a=e1_ref_cross_e1, b=self.e0, degree=1)
        psi = Expression('atan2(a,b)', a=e1_ref_cross_e1_dot_e0, b=e1_dot_e1_ref, degree=1)
        self.psi = interpolate(psi, self.V)

    def __eq__(self, other: 'FrameFenics') -> bool:
        # Convert to numpy for equality check
        f1 = self.to_numpy()
        f2 = other.to_numpy()
        return f1 == f2


class FrameNumpy(Frame):
    def __init__(
            self,
            x: np.ndarray = None,
            psi: np.ndarray = None,
            e0: np.ndarray = None,
            e1: np.ndarray = None,
            e2: np.ndarray = None,
            alpha: np.ndarray = None,
            beta: np.ndarray = None,
            gamma: np.ndarray = None,
            worm: 'Worm' = None,
            estimate_psi: bool = False,
            estimate_psi_window_size: float = PSI_ESTIMATE_WS_DEFAULT,
            calculate_components: bool = False
    ):
        super().__init__(x, psi, e0, e1, e2, alpha, beta, gamma, worm, estimate_psi, estimate_psi_window_size)

        if alpha is None or beta is None or gamma is None:
            self.alpha, self.beta, self.gamma = self._init_curvature_and_twist(worm)
        else:
            self.alpha, self.beta, self.gamma = alpha, beta, gamma

        # Calculate the frame components from x and psi
        if calculate_components:
            self.calculate_components()

    def clone(self) -> 'FrameNumpy':
        args = {k: getattr(self, k).copy() for k in FRAME_KEYS}
        return FrameNumpy(**args)

    def _init_x(self, worm: 'Worm') -> np.ndarray:
        shape = (3, worm.N)
        x = np.zeros(shape)
        return x

    def _init_psi(self, worm: 'Worm' = None, estimate: bool = False, window_size: float = PSI_ESTIMATE_WS_DEFAULT) \
            -> np.ndarray:
        if estimate:
            psi = estimate_psi_from_x(self.x, window_size)
        else:
            if worm is None:
                N = self.x.shape[-1]
            else:
                N = worm.N
            psi = np.zeros(N)
        return psi

    def _init_components(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        shape = self.x.shape
        e0 = np.zeros(shape)
        e1 = np.zeros(shape)
        e2 = np.zeros(shape)
        return e0, e1, e2

    def _init_curvature_and_twist(self, worm: 'Worm' = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        if worm is None:
            N = self.x.shape[-1]
        else:
            N = worm.N
        alpha = np.zeros(N)
        beta = np.zeros(N)
        gamma = np.zeros(N - 1)
        return alpha, beta, gamma

    def calculate_components(self):
        """
        Calculate the e0/e1/e2 orthonormal frame components from the midline x and the rotation angle psi.
        """

        # e0 - normal to cross section; points along the body
        dxds = np.gradient(self.x[0], edge_order=1)
        dyds = np.gradient(self.x[1], edge_order=1)
        dzds = np.gradient(self.x[2], edge_order=1)
        mu = np.sqrt(dxds**2 + dyds**2 + dzds**2)

        # Numpy and fenics use opposite directions for the curve, so flip here
        tau = -np.array([dxds, dyds, dzds]) / mu
        e0 = tau / np.linalg.norm(tau, axis=0)

        # Convert e0 to spherical coordinates to find theta/phi
        e0_x, e0_y, e0_z = e0[0], e0[1], e0[2]
        theta0 = np.arccos(e0_z)
        phi0 = np.arctan2(e0_y, e0_x)

        # Let e1 be the derivative of e0 wrt theta
        e1 = np.array([
            np.cos(theta0) * np.cos(phi0),
            np.cos(theta0) * np.sin(phi0),
            -np.sin(theta0)
        ])

        # Then apply the rotation of e1 around e0 by psi
        e1 = e1 * np.cos(self.psi) \
             + np.cross(e0, e1, axis=0) * np.sin(self.psi) \
             + e0 * (e0 * e1).sum(axis=0) * (1 - np.cos(self.psi))
        e1 = e1 / np.linalg.norm(e1, axis=0)

        # e2 is found by cross product
        e2 = np.cross(e0, e1, axis=0)
        e2 = e2 / np.linalg.norm(e2, axis=0)

        self.e0 = e0
        self.e1 = e1
        self.e2 = e2

    def to_fenics(self, worm: 'Worm', calculate_components=False) -> FrameFenics:
        return FrameFenics(
            x=v2f(self.x, fs=worm.V3, name='x'),
            psi=v2f(self.psi, fs=worm.V, name='psi'),
            e0=v2f(self.e0, fs=worm.V3, name='e0'),
            e1=v2f(self.e1, fs=worm.V3, name='e1'),
            e2=v2f(self.e2, fs=worm.V3, name='e2'),
            worm=worm,
            calculate_components=calculate_components
        )

    def get_range(self):
        mins = self.x.min(axis=1)
        maxs = self.x.max(axis=1)
        return mins, maxs

    def get_bounding_box(self, zoom=1) -> Tuple[np.ndarray, np.ndarray]:
        mins, maxs = self.get_range()
        max_range = max(maxs - mins)
        means = mins + (maxs - mins) / 2
        mins = means - max_range / 2 / zoom
        maxs = means + max_range / 2 / zoom
        return mins, maxs

    def get_worm_length(self) -> float:
        return np.linalg.norm(self.x[:, :-1] - self.x[:, 1:], axis=0).sum()

    def __eq__(self, other: 'FrameNumpy') -> bool:
        return all(
            np.allclose(getattr(self, k), getattr(other, k))
            for k in FRAME_KEYS
        )


class FrameSequence(ABC):
    def __init__(
            self,
            frames: List[Frame] = None,
            x=None,
            psi=None,
            e0=None,
            e1=None,
            e2=None,
            alpha=None,
            beta=None,
            gamma=None,
    ):
        # Can't instantiate with nothing!
        assert not all(v is None for v in [frames, x, psi, e0, e1, e2])
        if frames is not None:
            # Build sequence from a list of frames
            frames = self._generate_sequence_from_list(frames)
        else:
            # Build sequence from components - at a minimum this must include x
            assert x is not None
            frames = self._generate_sequence_from_components(x, psi, e0, e1, e2, alpha, beta, gamma)

        self.frames = frames

    @abstractmethod
    def _generate_sequence_from_list(self, frames: List[Frame]):
        pass

    @abstractmethod
    def _generate_sequence_from_components(self, x, psi, e0, e1, e2, alpha, beta, gamma):
        pass

    @abstractmethod
    def clone(self) -> 'FrameSequence':
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass

    @abstractmethod
    def __getitem__(self, i) -> Frame:
        pass

    @abstractmethod
    def __eq__(self, other: 'FrameSequence') -> bool:
        pass

    @property
    def n_frames(self) -> int:
        return len(self)


class FrameSequenceFenics(FrameSequence):
    def __init__(
            self,
            frames: List[FrameFenics] = None,
            x: List[Function] = None,
            psi: List[Function] = None,
            e0: List[Function] = None,
            e1: List[Function] = None,
            e2: List[Function] = None,
            alpha: List[Function] = None,
            beta: List[Function] = None,
            gamma: List[Function] = None,
    ):
        super().__init__(frames, x, psi, e0, e1, e2, alpha, beta, gamma)

    def _generate_sequence_from_list(self, frames: List[FrameFenics]) -> List[FrameFenics]:
        return frames

    def _generate_sequence_from_components(
            self,
            x: List[Function],
            psi: List[Function],
            e0: List[Function],
            e1: List[Function],
            e2: List[Function],
            alpha: List[Function],
            beta: List[Function],
            gamma: List[Function],
    ) -> List[FrameFenics]:
        n_timesteps = len(x)
        frames = [
            FrameFenics(x=x[t], psi=psi[t], e0=e0[t], e1=e1[t], e2=e2[t], alpha=alpha[t], beta=beta[t], gamma=gamma[t])
            for t in range(n_timesteps)
        ]
        return frames

    def to_numpy(self) -> 'FrameSequenceNumpy':
        return FrameSequenceNumpy(
            frames=[
                self[t].to_numpy()
                for t in range(self.n_frames)
            ]
        )

    def clone(self) -> 'FrameSequenceFenics':
        return FrameSequenceFenics(
            frames=[
                self[t].clone()
                for t in range(self.n_frames)
            ]
        )

    def __len__(self) -> int:
        return len(self.frames)

    def __getitem__(self, i) -> FrameFenics:
        return self.frames[i]

    def __eq__(self, other: 'FrameSequenceFenics') -> bool:
        fs1 = self.to_numpy()
        fs2 = other.to_numpy()
        return fs1 == fs2


class FrameSequenceNumpy(FrameSequence):
    def __init__(
            self,
            frames: List[FrameNumpy] = None,
            x: np.ndarray = None,
            psi: np.ndarray = None,
            e0: np.ndarray = None,
            e1: np.ndarray = None,
            e2: np.ndarray = None,
            alpha: np.ndarray = None,
            beta: np.ndarray = None,
            gamma: np.ndarray = None,
            calculate_components: bool = False
    ):
        self.calculate_components = calculate_components
        super().__init__(frames, x, psi, e0, e1, e2, alpha, beta, gamma)

    def _generate_sequence_from_list(self, frames: List[FrameNumpy]) -> dict:
        n_timesteps = len(frames)
        return {
            k: np.stack([getattr(frames[t], k) for t in range(n_timesteps)])
            for k in FRAME_KEYS
        }

    def _generate_sequence_from_components(
            self,
            x: np.ndarray = None,
            psi: np.ndarray = None,
            e0: np.ndarray = None,
            e1: np.ndarray = None,
            e2: np.ndarray = None,
            alpha: np.ndarray = None,
            beta: np.ndarray = None,
            gamma: np.ndarray = None,
    ) -> dict:
        if self.calculate_components:
            assert all(ei is None for ei in [e0, e1, e2]), \
                'Calculating components would override passed arguments. Aborting.'
            assert psi is not None, \
                'Calculating components requires psi. Aborting.'

            # Calculate the e0/e1/e2 components from x and psi
            e0 = np.zeros_like(x)
            e1 = np.zeros_like(x)
            e2 = np.zeros_like(x)
            for t in range(x.shape[0]):
                F = FrameNumpy(x=x[t], psi=psi[t], calculate_components=True)
                e0[t] = F.e0
                e1[t] = F.e1
                e2[t] = F.e2

        return {
            'x': x,
            'psi': psi,
            'e0': e0,
            'e1': e1,
            'e2': e2,
            'alpha': alpha,
            'beta': beta,
            'gamma': gamma,
        }

    def to_fenics(self, worm: 'Worm', calculate_components=False) -> 'FrameSequenceFenics':
        return FrameSequenceFenics(
            frames=[
                self[t].to_fenics(worm, calculate_components)
                for t in range(self.n_frames)
            ]
        )

    def clone(self) -> 'FrameSequenceNumpy':
        args = {
            k: self.frames[k].copy() if self.frames[k] is not None else None
            for k in FRAME_KEYS
        }
        return FrameSequenceNumpy(**args)

    def get_range(self) -> Tuple[np.ndarray, np.ndarray]:
        # Get common scale
        mins = np.array([np.inf, np.inf, np.inf])
        maxs = np.array([-np.inf, -np.inf, -np.inf])
        for i in range(len(self)):
            f_min, f_max = self[i].get_range()
            mins = np.minimum(mins, f_min)
            maxs = np.maximum(maxs, f_max)
        return mins, maxs

    def get_bounding_box(self, zoom=1) -> Tuple[np.ndarray, np.ndarray]:
        mins, maxs = self.get_range()
        max_range = max(maxs - mins)
        means = mins + (maxs - mins) / 2
        mins = means - max_range / 2 / zoom
        maxs = means + max_range / 2 / zoom
        return mins, maxs

    def __len__(self) -> int:
        return len(self.frames['x'])

    def __getitem__(self, i) -> Union['FrameSequenceNumpy', FrameNumpy]:
        if type(i) == slice:
            frames = []
            start = 0 if i.start is None else i.start
            stop = len(self) if i.stop is None else i.stop
            for j in range(start, stop):
                frames.append(self[j])
            return FrameSequenceNumpy(frames=frames)
        elif type(i) == int:
            args = {
                k: self.frames[k][i] if self.frames[k] is not None else None
                for k in FRAME_KEYS
            }
            return FrameNumpy(**args)
        else:
            raise ValueError(f'Unrecognised accessor type: {type(i)}.')

    def __getattr__(self, k):
        if k in FRAME_KEYS:
            return self.frames[k]
        else:
            raise AttributeError(f'Key: "{k}" not found.')

    def __eq__(self, other: 'FrameSequenceNumpy') -> bool:
        return all(
            np.allclose(getattr(self, k), getattr(other, k))
            for k in FRAME_KEYS
        )
