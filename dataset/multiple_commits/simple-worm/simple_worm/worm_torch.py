import resource
from multiprocessing import Pool
from typing import Tuple, Optional, List, Dict

import torch
import torch.nn as nn

from simple_worm.control_gates_torch import ControlGateTorch
from simple_worm.controls import CONTROL_KEYS
from simple_worm.controls_torch import ControlSequenceBatchTorch, ControlSequenceTorch
from simple_worm.frame import FRAME_KEYS
from simple_worm.frame_torch import FrameTorch, FrameBatchTorch, FrameSequenceBatchTorch, FrameSequenceTorch
from simple_worm.losses import N_ALL_LOSSES
from simple_worm.losses_torch import LossesTorch
from simple_worm.material_parameters_torch import MaterialParametersBatchTorch, MaterialParametersTorch
from simple_worm.worm import LINEAR_SOLVER_DEFAULT
from simple_worm.worm_inv import WormInv, MAX_ALPHA_BETA_DEFAULT, MAX_GAMMA_DEFAULT, INVERSE_OPT_LIBRARY_DEFAULT, \
    INVERSE_OPT_METHOD_DEFAULT, INVERSE_OPT_MAX_ITER_DEFAULT, INVERSE_OPT_TOL_DEFAULT, MKL_THREADS_DEFAULT

# Fixes bug with large batches where multiprocessing hangs with error: "RuntimeError: received 0 items of ancdata"
# https://github.com/pytorch/pytorch/issues/973#issuecomment-346405667
rlimit = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (4096, rlimit[1]))


class DummyContext(object):
    """
    Used to simulate a autograd ctx object when parallel processing.
    """
    pass


class WormFunction(torch.autograd.Function):
    @staticmethod
    def forward(
            ctx,
            worm: WormInv,
            MP_vec: torch.Tensor,
            x0: torch.Tensor,
            psi0: torch.Tensor,
            alpha: torch.Tensor,
            beta: torch.Tensor,
            gamma: torch.Tensor,
            alpha_gate: ControlGateTorch = None,
            beta_gate: ControlGateTorch = None,
            gamma_gate: ControlGateTorch = None,
            calculate_inverse: bool = False,
            X_target: torch.Tensor = None
    ):
        if calculate_inverse:
            assert X_target is not None

        # Simulation run time
        n_timesteps = len(alpha)
        T = worm.dt * n_timesteps

        # Store inputs for backwards pass
        MP = MaterialParametersTorch(*MP_vec)
        F0 = FrameTorch(x0, psi0)
        CS = ControlSequenceTorch(
            alpha=alpha,
            beta=beta,
            gamma=gamma,
            alpha_gate=alpha_gate,
            beta_gate=beta_gate,
            gamma_gate=gamma_gate,
        )
        ctx.MP = MP
        ctx.F0 = F0
        ctx.CS = CS

        # Convert tensor inputs to fenics variables
        MPf = MP.to_fenics()
        F0f = F0.to_fenics(worm)
        CSf = CS.to_fenics(worm)

        # Convert targets to fenics variables
        if X_target is not None:
            FS_target = FrameSequenceTorch(x=X_target)
            FSf_target = FS_target.to_fenics(worm)
        else:
            FSf_target = None

        if calculate_inverse:
            # Execute forward and backwards pass in solver
            FSf, L, MPf_opt, F0f_opt, CSf_opt, FSf_opt, L_opt = worm.solve_both(T, MPf, F0f, CSf, FSf_target)

            # Convert fenics controls to torch tensors
            MP_opt = MPf_opt.to_torch()
            F0_opt = F0f_opt.to_torch()
            CS_opt = CSf_opt.to_torch()
            FS_opt = FSf_opt.to_torch()
            L_opt = torch.from_numpy(L_opt.to_numpy())

            # Save optimals for gradient calculation
            ctx.MP_opt = MP_opt
            ctx.F0_opt = F0_opt
            ctx.CS_opt = CS_opt
        else:
            # Only execute forward solver
            FSf, L = worm.solve_forward(T, MPf, F0f, CSf, FSf_target)

            # Dummy optimals
            MP_opt = MPf.to_torch()
            F0_opt = FrameTorch(worm=worm)
            CS_opt = ControlSequenceTorch(worm=worm, n_timesteps=n_timesteps)
            FS_opt = FSf.to_torch()

            # Dummy losses
            L_opt = torch.zeros(N_ALL_LOSSES)

        # Convert forward model outputs to torch tensors
        FS = FSf.to_torch()
        if L is None:
            L = torch.zeros(N_ALL_LOSSES)
        else:
            L = torch.from_numpy(L.to_numpy())

        return *FS.parameters(), L, MP_opt.parameter_vector(), *F0_opt.parameters(), \
               *CS_opt.parameters(include_gates=False), *FS_opt.parameters(), L_opt

    @staticmethod
    def prepare_results(outs: List[torch.Tensor], gates: Dict[str, Optional[ControlGateTorch]] = None):
        # Sort outputs into parameter groups
        FS_params = {k: outs[i] for i, k in enumerate(FRAME_KEYS)}
        offset = len(FRAME_KEYS)
        L_params = outs[offset]
        offset += 1
        MP_opt_params = outs[offset]
        offset += 1
        F0_opt_params = {k: outs[offset + i] for i, k in enumerate(FRAME_KEYS)}
        offset += len(FRAME_KEYS)
        CS_opt_params = {k: outs[offset + i] for i, k in enumerate(CONTROL_KEYS)}
        offset += len(CONTROL_KEYS)
        FS_opt_params = {k: outs[offset + i] for i, k in enumerate(FRAME_KEYS)}
        offset += len(FRAME_KEYS)
        L_opt_params = outs[offset]

        # Instantiate batched output wrappers
        FS = FrameSequenceBatchTorch(**FS_params)
        L = LossesTorch(L_params)
        MP_opt = MaterialParametersBatchTorch(*MP_opt_params.T)
        F0_opt = FrameBatchTorch(**F0_opt_params)
        CS_opt = ControlSequenceBatchTorch(**CS_opt_params, **({} if gates is None else gates))
        FS_opt = FrameSequenceBatchTorch(**FS_opt_params)
        L_opt = LossesTorch(L_opt_params)

        return FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt

    @staticmethod
    def backward(ctx, *args):
        assert hasattr(ctx, 'MP_opt'), 'Optimal MP not in ctx, has inverse problem been solved?'
        assert hasattr(ctx, 'F0_opt'), 'Optimal F0 not in ctx, has inverse problem been solved?'
        assert hasattr(ctx, 'CS_opt'), 'Optimal controls not in ctx, has inverse problem been solved?'

        # Gradients taken simply as the difference with the optimals found by the solver
        grads = {
            'worm': None,
            'MP': ctx.MP.parameter_vector() - ctx.MP_opt.parameter_vector(),
            'x0': None,
            'psi0': ctx.F0.psi - ctx.F0_opt.psi,
            'alpha': ctx.CS.alpha - ctx.CS_opt.alpha,
            'beta': ctx.CS.beta - ctx.CS_opt.beta,
            'gamma': ctx.CS.gamma - ctx.CS_opt.gamma,
            'alpha_gate': None,
            'beta_gate': None,
            'gamma_gate': None,
            'calculate_inverse': None,
            'X_target': None,
        }

        return tuple(grads.values())


class WormFunctionParallel(torch.autograd.Function):
    @staticmethod
    def forward(
            ctx,
            worm_mod: 'WormModule',
            MP: torch.Tensor,
            x0: torch.Tensor,
            psi0: torch.Tensor,
            alpha: torch.Tensor,
            beta: torch.Tensor,
            gamma: torch.Tensor,
            alpha_gate: ControlGateTorch = None,
            beta_gate: ControlGateTorch = None,
            gamma_gate: ControlGateTorch = None,
            calculate_inverse: bool = False,
            X_target: torch.Tensor = None
    ):
        print(f'Starting simulation pool (n_workers={worm_mod.n_workers})')

        # Pass arguments to recreate an identical worm module in the separate processes, more robust than sharing or serialising
        worm = worm_mod.worm_solver
        worm_args = {
            'N': worm.N,
            'dt': worm.dt,
            'forward_solver': worm.forward_solver,
            'forward_solver_opts': worm.forward_solver_opts,
            'optimise_MP_K': worm.optimise_MP_K,
            'optimise_MP_K_rot': worm.optimise_MP_K_rot,
            'optimise_MP_A': worm.optimise_MP_A,
            'optimise_MP_B': worm.optimise_MP_B,
            'optimise_MP_C': worm.optimise_MP_C,
            'optimise_MP_D': worm.optimise_MP_D,
            'optimise_F0': worm.optimise_F0,
            'optimise_CS': worm.optimise_CS,
            'max_alpha_beta': worm.max_alpha_beta,
            'max_gamma': worm.max_gamma,
            'reg_weights': worm.reg_weights,
            'inverse_opt_max_iter': worm.inverse_opt_max_iter,
            'inverse_opt_tol': worm.inverse_opt_tol,
            'quiet': True
        }
        MP = MaterialParametersBatchTorch(*MP)
        F0 = FrameBatchTorch(x=x0, psi=psi0)
        CS = ControlSequenceBatchTorch(
            alpha=alpha,
            beta=beta,
            gamma=gamma,
            alpha_gate=alpha_gate,
            beta_gate=beta_gate,
            gamma_gate=gamma_gate,
        )
        with Pool(worm_mod.n_workers) as pool:
            args = []
            for i in range(worm_mod.batch_size):
                args_i = {
                    'batch_size': worm_mod.batch_size,
                    'worm_args': worm_args,
                    'MP': MP[i],
                    'F0': F0[i],
                    'CS': CS[i],
                    'calculate_inverse': calculate_inverse,
                    'X_target': None if not calculate_inverse else X_target[i],
                }
                args.append(args_i)

            outs = pool.map(
                WormFunctionParallel.solve_single,
                [[i, args[i]] for i in range(worm_mod.batch_size)]
            )

        outs = tuple(torch.stack(out) for out in zip(*outs))
        FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = WormFunction.prepare_results(outs)

        ctx.MP = MP
        ctx.F0 = F0
        ctx.CS = CS
        ctx.MP_opt = MP_opt
        ctx.F0_opt = F0_opt
        ctx.CS_opt = CS_opt
        ctx.FS_opt = FS_opt

        return outs

    @staticmethod
    def solve_single(args):
        batch_idx = args[0]
        fn_args = args[1]
        batch_size = fn_args['batch_size']
        print(f'#{batch_idx + 1}/{batch_size} started')
        worm = WormInv(**fn_args['worm_args'])
        ctx = DummyContext()

        # Solve using single-process implementation
        outs = WormFunction.forward(
            ctx,
            worm,
            fn_args['MP'].parameter_vector(),
            fn_args['F0'].x,
            fn_args['F0'].psi,
            *fn_args['CS'].parameters(as_dict=False),
            calculate_inverse=fn_args['calculate_inverse'],
            X_target=fn_args['X_target'],
        )

        print(f'#{batch_idx + 1}/{batch_size} finished')

        return outs

    @staticmethod
    def backward(*args):
        return WormFunction.backward(*args)


class WormModule(nn.Module):
    def __init__(
            self,
            N: int,
            dt: float,
            batch_size: int,
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
            reg_weights: dict = {},
            max_alpha_beta: float = MAX_ALPHA_BETA_DEFAULT,
            max_gamma: float = MAX_GAMMA_DEFAULT,
            inverse_opt_library: str = INVERSE_OPT_LIBRARY_DEFAULT,
            inverse_opt_method: str = INVERSE_OPT_METHOD_DEFAULT,
            inverse_opt_max_iter: int = INVERSE_OPT_MAX_ITER_DEFAULT,
            inverse_opt_tol: float = INVERSE_OPT_TOL_DEFAULT,
            inverse_opt_opts: dict = None,
            mkl_threads: int = MKL_THREADS_DEFAULT,
            parallel: bool = False,
            n_workers: int = 2,
            quiet=False
    ):
        super().__init__()

        # Initialise worm solver
        self.worm_solver = WormInv(
            N=N,
            dt=dt,
            forward_solver=forward_solver,
            forward_solver_opts=forward_solver_opts,
            optimise_MP_K=optimise_MP_K,
            optimise_MP_K_rot=optimise_MP_K_rot,
            optimise_MP_A=optimise_MP_A,
            optimise_MP_B=optimise_MP_B,
            optimise_MP_C=optimise_MP_C,
            optimise_MP_D=optimise_MP_D,
            optimise_F0=optimise_F0,
            optimise_CS=optimise_CS,
            reg_weights=reg_weights,
            max_alpha_beta=max_alpha_beta,
            max_gamma=max_gamma,
            inverse_opt_library=inverse_opt_library,
            inverse_opt_method=inverse_opt_method,
            inverse_opt_max_iter=inverse_opt_max_iter,
            inverse_opt_tol=inverse_opt_tol,
            inverse_opt_opts=inverse_opt_opts,
            mkl_threads=mkl_threads,
            quiet=quiet
        )

        # Process batches in parallel
        self.batch_size = batch_size
        self.parallel = parallel
        self.n_workers = n_workers

    def forward(
            self,
            MP: MaterialParametersBatchTorch,
            F0: FrameBatchTorch,
            CS: ControlSequenceBatchTorch,
            calculate_inverse: bool = False,
            FS_target: FrameSequenceBatchTorch = None
    ) -> Tuple[
        FrameSequenceBatchTorch,
        LossesTorch,
        Optional[MaterialParametersBatchTorch],
        Optional[FrameBatchTorch],
        Optional[ControlSequenceBatchTorch],
        Optional[FrameSequenceBatchTorch],
        Optional[LossesTorch]
    ]:
        if self.parallel:
            args = self, MP.parameter_vector(), F0.x, F0.psi, *CS.parameters(), calculate_inverse
            if FS_target is not None:
                args += (FS_target.x,)
            outs = WormFunctionParallel.apply(*args)
        else:
            outs = []
            for i in range(self.batch_size):
                args = self.worm_solver, MP[i].parameter_vector(), F0[i].x, F0[i].psi, \
                       *CS[i].parameters(), calculate_inverse
                if FS_target is not None:
                    args += (FS_target[i].x,)
                out = WormFunction.apply(*args)
                outs.append(out)
            outs = tuple(torch.stack(out) for out in zip(*outs))

        # Rearrange by output index and stack over number of input sets
        FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = WormFunction.prepare_results(outs, CS.get_gates())

        # Set the outputs as requiring grad if the inputs require it
        if MP.requires_grad() or F0.requires_grad() or CS.requires_grad():
            FS.x.requires_grad_(True)
            FS.psi.requires_grad_(True)

        # Prepare outputs
        ret = (FS, L,)
        if calculate_inverse:
            ret += (MP_opt, F0_opt, CS_opt, FS_opt, L_opt)

        return ret
