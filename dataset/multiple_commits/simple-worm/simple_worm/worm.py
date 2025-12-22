from typing import Tuple

import numpy as np
from fenics import *

from simple_worm.controls import ControlsFenics, ControlSequenceFenics
from simple_worm.frame import FrameFenics, FrameSequenceFenics
from simple_worm.material_parameters import MaterialParametersFenics
from simple_worm.util import f2n

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass

# global geometry helpers
dxL = dx(scheme='vertex', degree=1,
         metadata={'representation': 'quadrature',
                   'degree': 1})


def grad(function): return Dx(function, 0)


LINEAR_SOLVER_DEFAULT = 'mumps'


class Worm:
    """
    Class for holding all the information about the worm geometry and to
    update the geometry.
    """

    def __init__(
            self,
            N: int,
            dt: float,
            forward_solver: str = LINEAR_SOLVER_DEFAULT,
            forward_solver_opts: dict = None,
            quiet: bool = False
    ):
        # Domain
        self.N = N
        self.dt = dt
        self.t = 0.
        self.quiet = quiet
        self.parameters: MaterialParametersFenics = None

        # Solver options
        self.forward_solver = forward_solver
        if forward_solver_opts is None:
            forward_solver_opts = {}
        self.forward_solver_opts = forward_solver_opts
        self._print(f'Using solver: {self.forward_solver}. With parameters: {self.forward_solver_opts}.')

        # Default initial frame
        self.x0_default = Expression(('x[0]', '0', '0'), degree=1)
        self.psi0_default = Expression('0', degree=1)

        # Default forces
        self.alpha_pref_default = Expression('0', degree=1)
        self.beta_pref_default = Expression('0', degree=1)
        self.gamma_pref_default = Expression('0', degree=0)

        # Set up function spaces
        self._init_spaces()
        self.F: FrameFenics = None
        self.F_op = None
        self.L = None
        self.bc = None

    # ---------- Init functions ----------

    def initialise(
            self,
            MP: MaterialParametersFenics = None,
            F0: FrameFenics = None,
            CS: ControlSequenceFenics = None,
            n_timesteps: int = 1,
    ) -> Tuple[MaterialParametersFenics, FrameFenics, ControlSequenceFenics]:
        """
        Initialise/reset the simulation.
        """
        self.t = 0
        self._init_solutions()

        # Set material parameters
        if MP is None:
            MP = MaterialParametersFenics()
        self.parameters = MP

        # Set initial frame - ensuring the initial frame is computed
        if F0 is None:
            F0 = FrameFenics(worm=self)
        F0.calculate_components()
        self.F = F0.clone()

        # Set default controls
        if CS is None:
            CS = ControlSequenceFenics(worm=self, n_timesteps=n_timesteps)

        self._compute_initial_values()
        self._init_forms()

        return MP, F0, CS

    def _init_spaces(self):
        """
        Set up function spaces.
        """
        mesh = UnitIntervalMesh(self.N - 1)
        P1 = FiniteElement('Lagrange', mesh.ufl_cell(), 1)
        P0 = FiniteElement('DP', mesh.ufl_cell(), 0)
        P1_3 = MixedElement([P1] * 3)
        self.V = FunctionSpace(mesh, P1)
        self.V3 = FunctionSpace(mesh, P1_3)
        self.Q = FunctionSpace(mesh, P0)
        self.VV = [self.V3, self.V3, self.V3, self.V, self.Q, self.Q, self.Q]
        self.W = FunctionSpace(
            mesh,
            MixedElement([P1_3, P1_3, P1_3, P1, P0, P0, P0])
        )

    def _init_solutions(self):
        """
        Set up functions to hold state and solutions.
        """
        self.u_n = Function(self.W)
        self.alpha_pref = Function(self.V)
        self.beta_pref = Function(self.V)
        self.gamma_pref = Function(self.Q)

    # ---------- Main methods ----------

    def solve(
            self,
            T: float,
            MP: MaterialParametersFenics = None,
            F0: FrameFenics = None,
            CS: ControlSequenceFenics = None,
            reset: bool = True,
            project_outputs: bool = False,
            solver_parameters: dict = {}
    ) -> FrameSequenceFenics:
        """
        Run the forward model for T seconds.
        """
        n_timesteps = round(T / self.dt)
        if reset:
            MP, F0, CS = self.initialise(MP, F0, CS, n_timesteps)
        assert len(CS) == n_timesteps, 'Controls not available for every simulation step.'
        self._print(f'Solve forward (t={self.t:.3f}..{self.t + T:.3f} / n_steps={n_timesteps})')

        frames = []
        for i in range(n_timesteps):
            self._print(f't={self.t:.3f}')
            f_t = self.update_solution(CS[i], project_outputs=project_outputs, solver_parameters=solver_parameters)
            frames.append(f_t)
        FS = FrameSequenceFenics(frames=frames)

        return FS

    # ---------- Initial state and conditions ----------

    def _compute_initial_values(self):
        x0 = project(self.F.x, self.V3)
        mu0 = sqrt(dot(grad(x0), grad(x0)))
        kappa0 = self._compute_initial_curvature(mu0)
        gamma0 = self._compute_initial_twist(mu0)

        # Initialize global solution variables
        fa = FunctionAssigner(self.W, self.VV)
        fa.assign(self.u_n, [x0, Function(self.V3), kappa0, Function(self.V),
                             Function(self.Q), gamma0, Function(self.Q)])
        self.mu0 = mu0

    def _compute_initial_curvature(self, mu0) -> Function:
        # Set up problem for initial curvature
        x0 = self.F.x
        kappa_trial = TrialFunction(self.V3)
        kappa_test = TestFunction(self.V3)
        F0_kappa = dot(kappa_trial, kappa_test) * mu0 * dxL \
                   + inner(grad(x0), grad(kappa_test)) / mu0 * dx
        a0_kappa, L0_kappa = lhs(F0_kappa), rhs(F0_kappa)
        kappa0 = Function(self.V3)
        solve(a0_kappa == L0_kappa, kappa0)
        if np.isnan(kappa0.vector().sum()):
            raise RuntimeError('kappa0 contains NaNs')
        return kappa0

    def _compute_initial_twist(self, mu0) -> Function:
        # Set up problem for initial twist
        gamma = TrialFunction(self.Q)
        v = TestFunction(self.Q)
        F_gamma0 = (gamma - dot(grad(self.F.e1), self.F.e2) / mu0) * v * dx
        a_gamma0, L_gamma0 = lhs(F_gamma0), rhs(F_gamma0)
        gamma0 = Function(self.Q)
        solve(a_gamma0 == L_gamma0, gamma0)
        if np.isnan(gamma0.vector().sum()):
            raise RuntimeError('gamma0 contains NaNs')
        return gamma0

    def _init_forms(self):
        dt = self.dt

        # Geometry
        x_n, y_n, kappa_n, m_n, z_n, gamma_n, p_n = split(self.u_n)

        mu = sqrt(inner(grad(x_n), grad(x_n)))
        tau = grad(x_n) / mu
        tauv = self.F.e0

        tau_cross_kappa = cross(tau, kappa_n)
        tauv_cross_kappa = cross(tauv, kappa_n)

        tautau = outer(tau, tau)
        P = Identity(3) - tautau
        Pv = Identity(3) - outer(tauv, tauv)

        # Define variational problem
        u = TrialFunction(self.W)
        v = TestFunction(self.W)

        # Split test and trial functions
        x, y, kappa, m, z, gamma, p = split(u)
        phi_x, phi_y, phi_kappa, phi_m, phi_z, phi_gamma, phi_p = split(v)

        # Parameters
        KK = self.parameters.K * P + tautau
        K_rot = self.parameters.K_rot
        A, B, C, D = self.parameters.A, self.parameters.B, self.parameters.C, self.parameters.D

        # Variational form
        F_x = 1.0 / dt * dot(KK * (x - x_n), phi_x) * mu * dx \
              - p * dot(tau, grad(phi_x)) * dx \
              - dot(P * grad(y), grad(phi_x)) / mu * dx \
              - z * dot(tau_cross_kappa, grad(phi_x)) * dx

        F_y = dot(y - A * (kappa - self.alpha_pref * self.F.e1 - self.beta_pref * self.F.e2)
                  - B * (Pv * (kappa - kappa_n) / dt - m * tauv_cross_kappa),
                  phi_y) * mu * dx  # TODO wrong measure (should be dxL)

        F_w = inner(grad(x), grad(phi_kappa)) / mu * dx \
              + dot(kappa, phi_kappa) * mu * dxL

        F_m = -K_rot * m * phi_m * mu * dx \
              - z * grad(phi_m) * dx \
              + dot(y, tauv_cross_kappa) * phi_m * mu * dx

        F_z = (z - C * (gamma - self.gamma_pref) - D / dt *
               (gamma - gamma_n)) * phi_z * mu * dx

        F_gamma = 1.0 / dt * (gamma - gamma_n) * phi_gamma * mu * dx \
                  - grad(m) * phi_gamma * dx \
                  + dot(tau_cross_kappa, 1.0 / dt * grad(x - x_n)) \
                  * phi_gamma * dx

        F_p = (dot(tau, grad(x)) - self.mu0) * phi_p * dx

        F = F_x + F_y + F_w + F_m + F_z + F_gamma + F_p
        self.F_op, self.L = lhs(F), rhs(F)

        # Boundary conditions
        y_space = self.W.split()[1]
        y_b = Constant([0, 0, 0])
        kappa_space = self.W.split()[2]
        self.kappa_b = project(self.alpha_pref * self.F.e1 + self.beta_pref * self.F.e2, self.V3)
        self.bc = [
            DirichletBC(y_space, y_b, lambda x, o: o),
            DirichletBC(kappa_space, self.kappa_b, lambda x, o: o),
        ]

    # ---------- Main algorithm ----------

    def update_solution(
            self,
            C: ControlsFenics,
            project_outputs: bool = False,
            solver_parameters: dict = {}
    ) -> FrameFenics:
        """
        Run the model forward a single timestep.
        """
        self.t += self.dt

        # Update driving forces - use get method to apply any control gates
        self.alpha_pref.assign(C.get_alpha())
        self.beta_pref.assign(C.get_beta())
        self.gamma_pref.assign(C.get_gamma())

        # Update boundary data
        self.kappa_b.assign(
            project(
                self.alpha_pref * self.F.e1 + self.beta_pref * self.F.e2,
                self.V3
            )
        )

        # Compute and update solution
        u = Function(self.W)
        params = {
            **{'linear_solver': self.forward_solver},
            **self.forward_solver_opts,
            **solver_parameters
        }
        solve(self.F_op == self.L, u, bcs=self.bc,
              solver_parameters=params)
        if np.isnan(u.vector().sum()):
            raise RuntimeError('Solution u contains NaNs')
        self.u_n.assign(u)

        # Update frame
        x, y, kappa, m, z, gamma, p = split(u)
        varphi = m * self.dt
        self.F.update(x, varphi, kappa, gamma)
        if np.isnan(self.F.e1.vector().sum()):
            raise RuntimeError('Solution e1 contains NaNs')
        if np.isnan(self.F.e2.vector().sum()):
            raise RuntimeError('Solution e2 contains NaNs')

        # Calculate the outputs (psi, alpha, beta, gamma) only if required
        if project_outputs:
            self.F.project_outputs()

        # Return a copy of the updated frame
        return self.F.clone()

    # ---------- Helpers ----------

    def _print(self, s):
        # todo: proper logging!
        if not self.quiet:
            print(s)

    # ---------- Getters ----------

    def get_x(self) -> np.ndarray:
        """
        Returns the position of mid-line points as a numpy array.
        """
        return f2n(self.F.x)

    def get_e1(self) -> np.ndarray:
        """
        Returns the first component of cross section frame.
        """
        return f2n(self.F.e1)

    def get_e2(self) -> np.ndarray:
        """
        Returns the second component of cross section frame.
        """
        return f2n(self.F.e2)

    def get_alpha(self) -> np.ndarray:
        """
        Returns the curvature in the direction e1 (first frame direction).
        """
        kappa = self.u_n.split(deepcopy=True)[2]
        alpha_expr = dot(kappa, self.F.e1)
        alpha = project(alpha_expr, self.V)
        return f2n(alpha)

    def get_beta(self) -> np.ndarray:
        """
        Returns the curvature in the direction e2 (second frame direction).
        """
        kappa = self.u_n.split(deepcopy=True)[2]
        beta_expr = dot(kappa, self.F.e2)
        beta = project(beta_expr, self.V)
        return f2n(beta)

    def get_gamma(self) -> np.ndarray:
        """
        Return the twist of the frame about the mid-line.
        """
        gamma = self.u_n.split(deepcopy=True)[5]
        return f2n(gamma)
