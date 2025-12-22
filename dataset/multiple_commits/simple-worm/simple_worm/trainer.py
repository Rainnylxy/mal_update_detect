import os
import shutil
import time
from datetime import timedelta

import matplotlib.pyplot as plt
import numpy as np
import torch
import torch.nn as nn
from torch.utils.tensorboard import SummaryWriter

from simple_worm.controls import CONTROL_KEYS
from simple_worm.controls_torch import ControlSequenceTorch, ControlSequenceBatchTorch
from simple_worm.frame import FRAME_KEYS
from simple_worm.frame_torch import FrameTorch, FrameBatchTorch, FrameSequenceBatchTorch
from simple_worm.material_parameters import MP_KEYS
from simple_worm.material_parameters_torch import MaterialParametersTorch, MaterialParametersBatchTorch
from simple_worm.plot3d import generate_scatter_clip, plot_X_vs_target, plot_frame_components_vs_target, \
    plot_CS_vs_target, plot_FS_orthogonality, plot_FS_normality, plot_FS_3d, plot_CS_vs_output
from simple_worm.worm_torch import WormModule

LOGS_PATH = 'logs'
N_VID_EGS = 1  # number of training examples to show in the videos
START_TIMESTAMP = time.strftime('%Y-%m-%d_%H%M%S')


class Trainer:
    def __init__(
            self,
            N: int = 10,
            T: float = 1.,
            dt: float = 0.1,
            optim_MP_K: bool = False,
            optim_MP_K_rot: bool = False,
            optim_MP_A: bool = False,
            optim_MP_B: bool = False,
            optim_MP_C: bool = False,
            optim_MP_D: bool = False,
            optim_F0: bool = False,
            optim_CS: bool = False,
            target_params: dict = None,
            lr: float = 0.1,
            reg_weights: dict = {},
            inverse_opt_max_iter: int = 2,
            inverse_opt_tol: float = 1e-8,
            parallel_solvers: int = 0,
            save_videos: bool = False,
            save_plots: bool = False,
            checkpoint_every_n_steps: int = 0,
    ):
        # Domain
        self.N = N
        self.T = T
        self.dt = dt
        self.n_steps = int(T / dt)

        # Optimiser parameters
        self.optim_MP_K = optim_MP_K
        self.optim_MP_K_rot = optim_MP_K_rot
        self.optim_MP_A = optim_MP_A
        self.optim_MP_B = optim_MP_B
        self.optim_MP_C = optim_MP_C
        self.optim_MP_D = optim_MP_D
        self.optim_F0 = optim_F0
        self.optim_CS = optim_CS
        self.lr = lr

        # Inverse optimiser parameters
        self.reg_weights = reg_weights
        self.inverse_opt_max_iter = inverse_opt_max_iter
        self.inverse_opt_tol = inverse_opt_tol

        # Training params
        self.global_step = 0
        self.best_loss = 1.e10
        self.save_plots = save_plots
        self.save_videos = save_videos
        self.checkpoint_every_n_steps = checkpoint_every_n_steps

        # Worm module
        self.worm = WormModule(
            N,
            dt=dt,
            batch_size=1,
            optimise_MP_K=self.optim_MP_K,
            optimise_MP_K_rot=self.optim_MP_K_rot,
            optimise_MP_A=self.optim_MP_A,
            optimise_MP_B=self.optim_MP_B,
            optimise_MP_C=self.optim_MP_C,
            optimise_MP_D=self.optim_MP_D,
            optimise_F0=self.optim_F0,
            optimise_CS=self.optim_CS,
            reg_weights=reg_weights,
            inverse_opt_max_iter=inverse_opt_max_iter,
            inverse_opt_tol=inverse_opt_tol,
            parallel=parallel_solvers > 0,
            n_workers=parallel_solvers,
            quiet=False
        )
        self.FS_outs = []
        self.FS_labels = []

        self._init_params(target_params)
        self._build_optimiser()

    def logs_path(self, timestamp: str = None) -> str:
        if timestamp is None:
            timestamp = START_TIMESTAMP

        optimisers = []
        for k in ['K', 'K_rot', 'A', 'B', 'C', 'D']:
            if getattr(self, f'optim_MP_{k}'):
                optimisers.append(k)
        if self.optim_F0:
            optimisers.append('F0')
        if self.optim_CS:
            optimisers.append('CS')
        if len(optimisers):
            optimise_str = ',optim=' + ','.join(optimisers)
        else:
            optimise_str = ''

        return LOGS_PATH + f'/N={self.N},' \
                           f'T={self.T:.2f},' \
                           f'dt={self.dt:.2f}' \
                           f'{optimise_str}' \
                           f'/{timestamp}_' \
                           f'lr={self.lr:.1E},' \
                           f'rw={self.reg_weights},' \
                           f'ii={self.inverse_opt_max_iter},' \
                           f'it={self.inverse_opt_tol:.1E}'

    def _init_loggers(self):
        self.logger = SummaryWriter(self.logs_path(), flush_secs=5)

    def _init_params(self, target_params: dict = None):
        if target_params is None:
            target_params = {}

        # Generate targets
        self.MP_target, self.F0_target, self.CS_target, self.FS_target \
            = self._generate_test_target(**target_params)

        # Generate optimisable material parameters
        self.MP = self.MP_target.clone()

        # Add some noise
        with torch.no_grad():
            if self.optim_MP_K:
                self.MP.K.requires_grad = True
                self.MP.K.data += torch.randn_like(self.MP.K) * 2
            if self.optim_MP_K_rot:
                self.MP.K_rot.requires_grad = True
                self.MP.K_rot.data += torch.randn_like(self.MP.K_rot) * 2
            if self.optim_MP_A:
                self.MP.A.requires_grad = True
                self.MP.A.data += torch.randn_like(self.MP.A) * 1e-1
            if self.optim_MP_B:
                self.MP.B.requires_grad = True
                self.MP.B.data += torch.randn_like(self.MP.B) * 1e-1
            if self.optim_MP_C:
                self.MP.C.requires_grad = True
                self.MP.C.data += torch.randn_like(self.MP.C) * 1e-1
            if self.optim_MP_D:
                self.MP.D.requires_grad = True
                self.MP.D.data += torch.randn_like(self.MP.D) * 1e-1
            self.MP.clamp()

        # Generate optimisable initial frame
        if self.optim_F0:
            self.F0 = FrameTorch(
                x=self.F0_target.x,
                optimise=True
            )

            # Add some noise
            with torch.no_grad():
                self.F0.psi.normal_(std=1e-2)
        else:
            # Clone the target's initial frame if we aren't trying to learn it
            self.F0 = self.F0_target.clone()

        # Generate optimisable controls
        if self.optim_CS:
            self.CS = ControlSequenceTorch(
                worm=self.worm.worm_solver,
                n_timesteps=self.n_steps,
                optimise=True
            )

            # Add some noise
            with torch.no_grad():
                self.CS.alpha.normal_(std=1e-3)
                self.CS.beta.normal_(std=1e-3)
                self.CS.gamma.normal_(std=1e-5)
        else:
            # Clone the target controls if we aren't trying to learn them
            self.CS = self.CS_target.clone()

    def _generate_test_target(
            self,
            MP: MaterialParametersTorch = None,
            alpha_pref_freq: float = 1.,
            beta_pref_freq: float = 0.,
    ):
        print('Generating test target')

        # Set material parameters
        if MP is None:
            MP = MaterialParametersTorch(K=2)
        if not isinstance(MP, MaterialParametersBatchTorch):
            MP = MaterialParametersBatchTorch.from_list([MP])

        # Set initial frame
        x0 = torch.zeros((1, 3, self.N), dtype=torch.float64)
        x0[:, 0] = torch.linspace(start=0, end=1, steps=self.N)
        psi0 = torch.zeros((1, self.N), dtype=torch.float64)
        psi0[:] = torch.linspace(start=0, end=np.pi, steps=self.N)
        F0 = FrameBatchTorch(x=x0, psi=psi0)  # worm=self.worm.worm_solver)

        # Set controls
        CS = ControlSequenceBatchTorch(
            worm=self.worm.worm_solver,
            n_timesteps=self.n_steps,
            batch_size=1
        )

        # Set alpha/beta to propagating sine waves
        offset = 0.
        for i in range(self.n_steps):
            if alpha_pref_freq > 0:
                CS.alpha[:, i] = torch.sin(
                    alpha_pref_freq * 2 * np.pi * (torch.linspace(start=0, end=1, steps=self.N) + offset)
                )
            if beta_pref_freq > 0:
                CS.beta[:, i] = torch.sin(
                    beta_pref_freq * 2 * np.pi * (torch.linspace(start=0, end=1, steps=self.N) + offset)
                )
            offset += self.dt

        # Add a slight twist along the body
        eps = 1e-2
        CS.gamma[:] = torch.linspace(start=-eps, end=eps, steps=self.N - 1)

        # Run the model forward to generate the output
        FS = self.worm.forward(MP, F0, CS)

        return MP[0], F0[0], CS[0], FS[0]

    def _build_optimiser(self):
        # Losses
        self.LP0 = nn.MSELoss()
        self.LMP = {k: nn.MSELoss() for k in MP_KEYS}
        self.LF = {k: nn.MSELoss() for k in FRAME_KEYS}
        self.LC = {k: nn.MSELoss() for k in CONTROL_KEYS}

        params = []
        params_mp = []
        if self.optim_MP_K:
            params_mp.append(getattr(self.MP, 'K'))
        if self.optim_MP_K_rot:
            params_mp.append(getattr(self.MP, 'K_rot'))
        if self.optim_MP_A:
            params_mp.append(getattr(self.MP, 'A'))
        if self.optim_MP_B:
            params_mp.append(getattr(self.MP, 'B'))
        if self.optim_MP_C:
            params_mp.append(getattr(self.MP, 'C'))
        if self.optim_MP_D:
            params_mp.append(getattr(self.MP, 'D'))
        if len(params_mp) > 0:
            params.append({'params': params_mp})
        if self.optim_F0:
            params.append({'params': self.F0.parameters()})
        if self.optim_CS:
            params.append({'params': self.CS.parameters()})

        if len(params) == 0:
            params = [{'params': []}]

        # Optimiser
        self.optimiser = torch.optim.Adam(params, lr=self.lr)

    def configure_paths(self, renew_logs):
        if renew_logs:
            print('Removing previous log files...')
            shutil.rmtree(self.logs_path(), ignore_errors=True)
        os.makedirs(self.logs_path(), exist_ok=True)

    def save_checkpoint(self):
        save_dir = f'{self.logs_path()}/checkpoints'
        os.makedirs(save_dir, exist_ok=True)
        path = f'{save_dir}/step_{self.global_step}.chkpt'
        torch.save({
            'MP': self.MP.parameters(as_dict=True),
            'F0': self.F0.parameters(as_dict=True),
            'CS': self.CS.parameters(as_dict=True),
            'opt': self.optimiser.state_dict(),
            'global_step': self.global_step,
            'best_loss': self.best_loss,
        }, path)
        print(f'Saved checkpoint to {path}')

    def load_checkpoint(self, timestamp, step):
        path = f'{self.logs_path(timestamp=timestamp)}/checkpoints/step_{step}.chkpt'
        state = torch.load(path)
        for k in MP_KEYS:
            v = getattr(self.MP, k)
            v.data = state['MP'][k]
        self.F0.x.data = state['F0']['x']
        self.F0.psi.data = state['F0']['psi']
        for k in CONTROL_KEYS:
            self.CS.controls[k].data = state['CS'][k]
        self.optimiser.load_state_dict(state['opt'])
        self.global_step = state['global_step']
        self.best_loss = state['best_loss']
        print(f'Loaded checkpoint from {path}. Step = {self.global_step}.')

    def train(self, n_steps):
        self._init_loggers()  # need to call this here in case paths have changed
        start_step = self.global_step
        final_step = start_step + n_steps

        # Initial plots
        self._plot_F0_components()
        self._plot_CS()

        for step in range(self.global_step, final_step + 1):
            start_time = time.time()
            self._train_step(step, final_step)
            time_per_step = time.time() - start_time
            seconds_left = float((final_step - step) * time_per_step)
            print('Time per step: {}, Est. complete in: {}'.format(
                str(timedelta(seconds=time_per_step)),
                str(timedelta(seconds=seconds_left))))

            if self.checkpoint_every_n_steps > 0 and (step + 1) % self.checkpoint_every_n_steps == 0:
                self.save_checkpoint()

    def _train_step(self, step, final_step):
        # Make pseudo-batches
        MP_batch = MaterialParametersBatchTorch.from_list([self.MP])
        F0_batch = FrameBatchTorch.from_list([self.F0])
        CS_batch = ControlSequenceBatchTorch.from_list([self.CS])
        FS_target_batch = FrameSequenceBatchTorch.from_list([self.FS_target])

        # Forward simulation
        FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = self.worm.forward(
            MP=MP_batch,
            F0=F0_batch,
            CS=CS_batch,
            calculate_inverse=True,
            FS_target=FS_target_batch
        )

        # Remove batch dims
        FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = FS[0], L[0], MP_opt[0], F0_opt[0], CS_opt[0], FS_opt[0], L_opt[0]

        self.FS = FS
        self.FS_outs.append(FS.clone().to_numpy())
        self.FS_labels.append(f'X_{step}')

        # Calculate losses
        LP0 = self.LP0(self.F0.psi, self.F0_target.psi)
        LMP = {
            k: self.LMP[k](getattr(self.MP, k), getattr(self.MP_target, k))
            for k in MP_KEYS if getattr(self.MP_target, k) is not None
        }
        LF = {
            k: self.LF[k](getattr(self.FS, k), getattr(self.FS_target, k))
            for k in FRAME_KEYS if getattr(self.FS_target, k) is not None
        }
        if self.CS_target is not None:
            LC = {
                k: self.LC[k](getattr(self.CS, k), getattr(self.CS_target, k))
                for k in CONTROL_KEYS
            }
        else:
            LC = {}
        L = sum([*LMP.values(), LP0, *LF.values(), *LC.values()])

        # Calculate gradients and do optimisation step
        if self.MP.requires_grad() or self.F0.requires_grad() or self.CS.requires_grad():
            self.optimiser.zero_grad()
            LF['x'].backward()
            self.optimiser.step()
            if self.MP.requires_grad():
                self.MP.clamp()

        # Increment global step counter
        self.global_step += 1

        # Calculate norms
        parameter_norm_sum = 0.
        for p in self.CS.parameters():
            parameter_norm_sum += p.norm()

        # Write debug
        self.logger.add_scalar('loss/step', L, self.global_step)
        self.logger.add_scalar('loss_F0/LP0', LP0, self.global_step)
        for k, l in LMP.items():
            self.logger.add_scalar(f'loss_MP/L_{k}', l, self.global_step)
        for k, l in LF.items():
            self.logger.add_scalar(f'loss_FS/L_{k}', l, self.global_step)
        for k, l in LC.items():
            self.logger.add_scalar(f'loss_CS/L_{k}', l, self.global_step)
        self.logger.add_scalar('loss/norm', parameter_norm_sum, self.global_step)

        # Track ratios
        if self.MP.requires_grad():
            self.logger.add_scalar('MP_ratios/K_A', self.MP.K / self.MP.A, self.global_step)
            self.logger.add_scalar('MP_ratios/K_B', self.MP.K / self.MP.B, self.global_step)
            self.logger.add_scalar('MP_ratios/A_B', self.MP.A / self.MP.B, self.global_step)
            self.logger.add_scalar('MP_ratios/Kr_C', self.MP.K_rot / self.MP.C, self.global_step)
            self.logger.add_scalar('MP_ratios/Kr_D', self.MP.K_rot / self.MP.D, self.global_step)
            self.logger.add_scalar('MP_ratios/C_D', self.MP.C / self.MP.D, self.global_step)

        print(f'[{step + 1}/{final_step}]. Loss = {L:.5E} ('
              + ', '.join([f'L{k}={LMP[k]:.3E}' for k in LMP])
              + ', '
              + ', '.join([f'L{k}={LF[k]:.3E}' for k in LF])
              + f', LP0={LP0:.3E}, '
              + ', '.join([f'L{k}={LC[k]:.3E}' for k in LC])
              + ')')

        self._make_plots()

        return L

    def _make_plots(self):
        self._plot_X()
        self._plot_F0_components()
        self._plot_CS()
        self._plot_CS_vs_output()
        self._plot_FS_orthogonality()
        self._plot_FS_normality()
        self._plot_FS_3d()
        self._make_vids()

    def _plot_X(self):
        fig = plot_X_vs_target(
            FS=self.FS.to_numpy(),
            FS_target=self.FS_target.to_numpy()
        )
        self._save_plot('X')
        self.logger.add_figure('X', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _plot_F0_components(self):
        if not self.optim_F0:
            return
        fig = plot_frame_components_vs_target(
            F=self.F0.to_numpy(worm=self.worm.worm_solver, calculate_components=True),
            F_target=self.F0_target.to_numpy(worm=self.worm.worm_solver, calculate_components=True)
        )
        self._save_plot('F0')
        self.logger.add_figure('F0', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _plot_CS(self):
        if not self.optim_CS:
            return
        fig = plot_CS_vs_target(
            CS=self.CS.to_numpy(),
            CS_target=self.CS_target.to_numpy()
        )
        self._save_plot('CS')
        self.logger.add_figure('CS', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _plot_CS_vs_output(self):
        fig = plot_CS_vs_output(
            CS=self.CS.to_numpy(),
            FS=self.FS.to_numpy(),
            dt=self.dt
        )
        self._save_plot('CS_vs_out')
        self.logger.add_figure('CS_vs_out', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _plot_FS_orthogonality(self):
        fig = plot_FS_orthogonality(
            FS=self.FS.to_numpy()
        )
        self._save_plot('FS_orthogonality')
        self.logger.add_figure('FS_orthogonality', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _plot_FS_normality(self):
        fig = plot_FS_normality(
            FS=self.FS.to_numpy()
        )
        self._save_plot('FS_normality')
        self.logger.add_figure('FS_normality', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _plot_FS_3d(self):
        fig = plot_FS_3d(
            FSs=[self.FS.to_numpy(), self.FS_target.to_numpy()],
            CSs=[self.CS.to_numpy(), self.CS_target.to_numpy() if self.CS_target is not None else None],
            labels=['Attempt', 'Target']
        )
        self._save_plot('3d')
        self.logger.add_figure(f'3d', fig, self.global_step)
        self.logger.flush()
        plt.close(fig)

    def _make_vids(self):
        if not self.save_videos:
            return

        # Make vids
        if N_VID_EGS == 1:
            idxs = [len(self.FS_outs) - 1]
            X_outs_to_plot = [self.FS_outs[-1]]
            labels_to_plot = [self.FS_labels[-1]]
        elif len(self.FS_outs) > N_VID_EGS:
            idxs = np.round(np.linspace(0, len(self.FS_outs) - 1, N_VID_EGS)).astype(int)
            X_outs_to_plot = [self.FS_outs[i] for i in idxs]
            labels_to_plot = [self.FS_labels[i] for i in idxs]
        else:
            idxs = list(range(len(self.FS_outs)))
            X_outs_to_plot = self.FS_outs
            labels_to_plot = self.FS_labels
        print(f'Generating scatter clip with idxs={idxs}')

        generate_scatter_clip(
            clips=[self.FS_target.to_numpy(), *X_outs_to_plot],
            save_dir=self.logs_path() + '/vids',
            save_fn=str(self.global_step),
            labels=['Target', *[l for l in labels_to_plot]]
        )

    def _save_plot(self, plot_type):
        if self.save_plots:
            save_dir = self.logs_path() + f'/plots/{plot_type}'
            os.makedirs(save_dir, exist_ok=True)
            path = save_dir + f'/{self.global_step:04d}.svg'
            plt.savefig(path, bbox_inches='tight')
