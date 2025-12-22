from typing import Tuple

import mkl
import numpy as np
from fenics_adjoint import *

from simple_worm.controls import ControlsFenics, CONTROL_KEYS, ControlSequenceFenics
from simple_worm.frame import FrameFenics, FrameSequenceFenics
from simple_worm.losses import Losses
from simple_worm.material_parameters import MP_KEYS, MaterialParametersFenics
from simple_worm.worm import Worm, LINEAR_SOLVER_DEFAULT

MAX_ALPHA_BETA_DEFAULT = 2 * 2 * np.pi  # Equivalent to two full coils
MAX_GAMMA_DEFAULT = 2 * 2 * np.pi  # Equivalent to two full twists

INVERSE_SOLVER_LIBRARY_SCIPY = 'scipy'
INVERSE_SOLVER_LIBRARY_IPOPT = 'ipopt'

INVERSE_SOLVER_LIBRARY_OPTIONS = [INVERSE_SOLVER_LIBRARY_SCIPY, INVERSE_SOLVER_LIBRARY_IPOPT]

# Note: 'spral' method not working
INVERSE_SOLVER_METHODS = {
    INVERSE_SOLVER_LIBRARY_SCIPY: ['L-BFGS-B'],
    INVERSE_SOLVER_LIBRARY_IPOPT: ['ma27', 'ma57', 'ma77', 'ma86', 'ma97', 'pardiso', 'mumps']
}

INVERSE_OPT_LIBRARY_DEFAULT = INVERSE_SOLVER_LIBRARY_SCIPY
INVERSE_OPT_METHOD_DEFAULT = 'L-BFGS-B'

INVERSE_OPT_MAX_ITER_DEFAULT = 4
INVERSE_OPT_TOL_DEFAULT = 1e-8
MKL_THREADS_DEFAULT = 4


class WormInv(Worm):
    """
    Extends the forward model to provide an inverse solver.
    """

    def __init__(
            self,
            N: int,
            dt: float,
            forward_solver: str = LINEAR_SOLVER_DEFAULT,
            forward_solver_opts: dict = None,
            optimise_MP_K: bool = False,
            optimise_MP_K_rot: bool = False,
            optimise_MP_A: bool = False,
            optimise_MP_B: bool = False,
            optimise_MP_C: bool = False,
            optimise_MP_D: bool = False,
            optimise_F0: bool = True,
            optimise_CS: bool = True,
            reg_weights: dict = None,
            max_alpha_beta: float = MAX_ALPHA_BETA_DEFAULT,
            max_gamma: float = MAX_GAMMA_DEFAULT,
            inverse_opt_library: str = INVERSE_OPT_LIBRARY_DEFAULT,
            inverse_opt_method: str = INVERSE_OPT_METHOD_DEFAULT,
            inverse_opt_max_iter: int = INVERSE_OPT_MAX_ITER_DEFAULT,
            inverse_opt_tol: float = INVERSE_OPT_TOL_DEFAULT,
            inverse_opt_opts: dict = None,
            mkl_threads: int = MKL_THREADS_DEFAULT,
            quiet: bool = False
    ):
        super().__init__(
            N=N,
            dt=dt,
            forward_solver=forward_solver,
            forward_solver_opts=forward_solver_opts,
            quiet=quiet
        )

        # Which parameters should be optimised
        self.optimise_MP_K = optimise_MP_K
        self.optimise_MP_K_rot = optimise_MP_K_rot
        self.optimise_MP_A = optimise_MP_A
        self.optimise_MP_B = optimise_MP_B
        self.optimise_MP_C = optimise_MP_C
        self.optimise_MP_D = optimise_MP_D
        self.optimise_F0 = optimise_F0
        self.optimise_CS = optimise_CS

        # Regularisation weights and parameter bounds
        self.reg_weights = reg_weights
        self.max_alpha_beta = max_alpha_beta
        self.max_gamma = max_gamma

        # Optimisation library, method and options
        assert inverse_opt_library in INVERSE_SOLVER_LIBRARY_OPTIONS, \
            f'Unrecognised inverse solver library: {inverse_opt_library}. Accepted: {INVERSE_SOLVER_LIBRARY_OPTIONS}.'
        assert inverse_opt_method in INVERSE_SOLVER_METHODS[inverse_opt_library], \
            f'Unrecognised inverse solver method: {inverse_opt_method}. Accepted: {INVERSE_SOLVER_METHODS[inverse_opt_library]}.'
        self.inverse_opt_library = inverse_opt_library
        self.inverse_opt_method = inverse_opt_method
        self.inverse_opt_max_iter = inverse_opt_max_iter
        self.inverse_opt_tol = inverse_opt_tol
        if inverse_opt_opts is None:
            inverse_opt_opts = {}
        self.inverse_opt_opts = inverse_opt_opts

        # How many mkl threads to use
        self.mkl_threads = mkl_threads
        mkl.set_num_threads(mkl_threads)
        mkl.set_num_threads_local(mkl_threads)

    def initialise(
            self,
            MP: MaterialParametersFenics = None,
            F0: FrameFenics = None,
            CS: ControlSequenceFenics = None,
            n_timesteps: int = 1,
    ) -> Tuple[FrameFenics, ControlSequenceFenics]:
        """
        Clear the adjoint tape and reset the state.
        """
        tape = get_working_tape()
        tape.clear_tape()
        return super().initialise(MP, F0, CS, n_timesteps)

    def optimise_any(self) -> bool:
        return self.optimise_MP_K \
               or self.optimise_MP_K_rot \
               or self.optimise_MP_A \
               or self.optimise_MP_B \
               or self.optimise_MP_C \
               or self.optimise_MP_D \
               or self.optimise_F0 \
               or self.optimise_CS

    # ---------- Main methods ----------

    def solve_both(
            self,
            T: float,
            MP: MaterialParametersFenics,
            F0: FrameFenics,
            CS: ControlSequenceFenics,
            FS_target: FrameSequenceFenics
    ) -> Tuple[
        FrameSequenceFenics,
        Losses,
        MaterialParametersFenics,
        FrameFenics,
        ControlSequenceFenics,
        FrameSequenceFenics,
        Losses
    ]:
        """
        Run the model forward for T seconds and then solve the inverse problem.
        """

        # Solve forwards
        FS, L = self.solve_forward(T, MP, F0, CS, FS_target)

        # Solve inverse
        MP_opt, F0_opt, CS_opt = self.solve_inverse(T, MP, F0, CS, FS, FS_target, L)

        # Run forward again with the found optimals
        FS_opt, L_opt = self.solve_forward(T, MP_opt, F0_opt, CS_opt, FS_target)

        return FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt

    def solve_forward(
            self,
            T: float,
            MP: MaterialParametersFenics,
            F0: FrameFenics,
            CS: ControlSequenceFenics,
            FS_target: FrameSequenceFenics = None
    ) -> Tuple[
        FrameSequenceFenics,
        Losses
    ]:
        """
        Run the model forward for T seconds and calculate losses.
        """
        FS = super().solve(T, MP, F0, CS)
        if FS_target is not None:
            L = Losses(T, self.dt, F0, CS, FS, FS_target, self.reg_weights)
        else:
            L = None

        return FS, L

    def solve_inverse(
            self,
            T: float,
            MP: MaterialParametersFenics,
            F0: FrameFenics,
            CS: ControlSequenceFenics,
            FS: FrameSequenceFenics,
            FS_target: FrameSequenceFenics,
            L: Losses = None
    ) -> Tuple[MaterialParametersFenics, FrameFenics, ControlSequenceFenics]:
        """
        Solve the inverse problem.
        """
        n_timesteps = int(T / self.dt)
        assert len(FS) == len(FS_target) == n_timesteps, 'FS or FS_target incorrect size.'
        self._print('Solve inverse')

        # Calculate losses
        if L is None:
            L = Losses(T, self.dt, F0, CS, FS, FS_target, self.reg_weights)

        # Material parameters
        params_mp = [Control(getattr(MP, p)) for p in MP_KEYS]
        bounds_mp = MP.get_bounds()

        # Initial frame - defined along the body
        params_frame = [Control(F0.psi)]
        bounds_frame = [[-np.pi], [3 * np.pi]]  # actually clipped to [0,2pi]

        # Controls - defined for all time points
        params_controls = []
        for k in CONTROL_KEYS:
            for t in range(n_timesteps):
                p = getattr(CS[t], k)
                params_controls.append(Control(p))
        bounds_ab = [
            -self.max_alpha_beta * np.ones(n_timesteps * 2),
            self.max_alpha_beta * np.ones(n_timesteps * 2)
        ]
        bounds_g = [
            -self.max_gamma * np.ones(n_timesteps),
            self.max_gamma * np.ones(n_timesteps)
        ]

        # Sum up the weighted regularisation terms
        L_reg = L.get_weighted_reg_sum()

        # Build the reduced functional
        params = []
        bounds = [[], []]
        for i, k in enumerate(MP_KEYS):
            if getattr(self, f'optimise_MP_{k}'):
                params.append(params_mp[i])
                bounds[0].append(bounds_mp[0][i])
                bounds[1].append(bounds_mp[1][i])

        if self.optimise_F0:
            params.extend(params_frame)
            bounds[0].extend(bounds_frame[0])
            bounds[1].extend(bounds_frame[1])

        if self.optimise_CS:
            params.extend(params_controls)
            bounds[0].extend(bounds_ab[0])
            bounds[0].extend(bounds_g[0])
            bounds[1].extend(bounds_ab[1])
            bounds[1].extend(bounds_g[1])

        J = L.L_data + L_reg
        rf = ReducedFunctional(J, params)

        # Minimise functional to find the optimal controls
        if self.optimise_any():
            if self.inverse_opt_library == INVERSE_SOLVER_LIBRARY_SCIPY:
                opt_inputs = minimize(
                    rf,
                    bounds=bounds,
                    method=self.inverse_opt_method,
                    options={
                        'maxiter': self.inverse_opt_max_iter,
                        'gtol': self.inverse_opt_tol,
                        'disp': not self.quiet,
                        **self.inverse_opt_opts
                    }
                )

            elif self.inverse_opt_library == INVERSE_SOLVER_LIBRARY_IPOPT:
                bounds = np.array(bounds).T
                problem = MinimizationProblem(rf, bounds=bounds)
                parameters = {
                    'linear_solver': self.inverse_opt_method,
                    'acceptable_tol': self.inverse_opt_tol,
                    'maximum_iterations': self.inverse_opt_max_iter,
                    'print_level': 0 if self.quiet else 5,
                    **self.inverse_opt_opts,
                }
                solver = IPOPTSolver(problem, parameters=parameters)
                opt_inputs = solver.solve()

            if type(opt_inputs) != list:
                opt_inputs = [opt_inputs]

        # Split up results
        opt_mps = []
        for i, k in enumerate(MP_KEYS):
            if getattr(self, f'optimise_MP_{k}'):
                opt_mp_i = opt_inputs[0]
                opt_inputs = opt_inputs[1:]
            else:
                opt_mp_i = params_mp[i].control
            opt_mps.append(opt_mp_i)

        if self.optimise_F0:
            psi0_opt = opt_inputs[0]
            opt_inputs = opt_inputs[1:]
        else:
            psi0_opt = params_frame[0].control

        if self.optimise_CS:
            opt_ctrls = opt_inputs
        else:
            opt_ctrls = [p.control for p in params_controls]
        alpha_opt = opt_ctrls[0:n_timesteps]
        beta_opt = opt_ctrls[n_timesteps:n_timesteps * 2]
        gamma_opt = opt_ctrls[n_timesteps * 2:]

        # Build optimal material parameters
        mp_args = {k: float(opt_mps[i]) for i, k in enumerate(MP_KEYS)}
        MP_opt = MaterialParametersFenics(**mp_args)

        # Build optimal initial frame
        F0_opt = FrameFenics(
            x=F0.x,
            psi=psi0_opt,
            worm=self
        )

        # Build optimal control sequence
        CS_opt = ControlSequenceFenics([
            ControlsFenics(
                alpha=alpha_opt[t],
                beta=beta_opt[t],
                gamma=gamma_opt[t],
            )
            for t in range(n_timesteps)
        ])

        return MP_opt, F0_opt, CS_opt
