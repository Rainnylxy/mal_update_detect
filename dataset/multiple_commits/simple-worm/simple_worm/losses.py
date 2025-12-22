from typing import Dict, Union

import numpy as np
from fenics import *
from simple_worm.controls import ControlSequenceFenics, CONTROL_KEYS
from simple_worm.frame import FrameFenics, FrameSequenceFenics
from simple_worm.worm import dx, grad
from ufl.form import Form as uflForm

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass

REG_LOSS_TYPES = ['L2', 'grad_t', 'grad_x']
REG_LOSS_VARS = ['psi0', 'alpha', 'beta', 'gamma']
N_REG_LOSSES = len(REG_LOSS_TYPES) * len(REG_LOSS_VARS)
N_ALL_LOSSES = 1 + 1 + 1 + N_REG_LOSSES * 2


class Losses:
    """
    Calculates the data and regularisation losses.
    """

    def __init__(
            self,
            T: float,
            dt: float,
            F0: FrameFenics,
            CS: ControlSequenceFenics,
            FS: FrameSequenceFenics,
            FS_target: FrameSequenceFenics,
            reg_weights: dict = None
    ):
        self.T = T
        self.dt = dt
        self.n_timesteps = int(T / self.dt)
        self.F0 = F0
        self.CS = CS
        self.FS = FS
        self.FS_target = FS_target
        self.reg_weights = self._init_regularisation_weights(reg_weights)
        self.L_data = self._calculate_data_loss()
        self.L_reg = self._calculate_regularisation_losses()

    @staticmethod
    def _init_regularisation_weights(reg_weights: dict = None) -> Dict[str, Dict[str, float]]:
        """
        Set up regularisation weights, defaulting to 0 everywhere and checking nothing invalid is requested.
        """
        rw = {}
        for loss in REG_LOSS_TYPES:
            rw[loss] = {}
            for k in REG_LOSS_VARS:
                w = 0
                if loss in reg_weights and k in reg_weights[loss]:
                    w = reg_weights[loss][k]
                    assert not (k == 'psi0' and loss == 'L2'), \
                        'L2 penalty on psi0 makes no sense!'
                    assert not (k == 'psi0' and loss == 'grad_t'), \
                        'Time derivative of psi0 makes no sense!'
                    assert not (k == 'gamma' and loss == 'grad_x'), \
                        'Can\'t take spatial gradient of gamma since it is piecewise-constant!'
                rw[loss][k] = w

        return rw

    def _calculate_data_loss(self) -> AdjFloat:
        """
        Calculate the L2 loss between the output frame sequence and the target.
        """
        L = 0
        for t in range(self.n_timesteps):
            # Implement a trapezoidal rule
            if t == self.n_timesteps - 1:
                weight = 0.5
            else:
                weight = 1
            L += weight * self.dt * (self.FS[t].x - self.FS_target[t].x)**2 * dx
        L = assemble(L) / self.T

        return L

    def _calculate_regularisation_losses(self) -> Dict[str, Dict[str, Union[int, float, uflForm]]]:
        """
        Calculate the regularisation losses.
        """
        n_timesteps = int(self.T / self.dt)

        # Set up regularisation loss sums
        reg_losses = {}
        for loss in REG_LOSS_TYPES:
            reg_losses[loss] = {}
            for k in REG_LOSS_VARS:
                reg_losses[loss][k] = 0

        # Worm "segment length"
        mu = sqrt(dot(grad(self.F0.x), grad(self.F0.x)))

        # Frame - smoothing in space only
        grad_x = (grad(self.F0.e1)**2 + grad(self.F0.e2)**2) / mu * dx
        reg_losses['grad_x']['psi0'] = grad_x

        # Controls - defined for all time points
        for k in CONTROL_KEYS:
            L2 = 0
            grad_t = 0
            grad_x = 0

            for t in range(n_timesteps):
                mu = sqrt(dot(grad(self.FS[t].x), grad(self.FS[t].x)))
                p = getattr(self.CS[t], k)

                # L2 penalty - smaller forcings are preferable
                L2 += p**2 * mu * self.dt / self.T * dx

                # Smoothing in time
                if t < n_timesteps - 1:
                    p_next = getattr(self.CS[t + 1], k)
                    grad_t += (p_next - p)**2 * mu / self.dt / self.T * dx

                # Smoothing in space
                if k != 'gamma':
                    # Can't take spatial gradient of gamma since it is piecewise-constant
                    grad_x += grad(p)**2 / mu * self.dt / self.T * dx

            reg_losses['L2'][k] = L2
            reg_losses['grad_t'][k] = grad_t
            reg_losses['grad_x'][k] = grad_x

        return reg_losses

    def get_weighted_reg_sum(self) -> AdjFloat:
        """
        Calculate the weighted sum of the regularisation losses.
        """
        reg_sum = 0
        for loss, rv in self.L_reg.items():
            for k, fv in rv.items():
                if self.reg_weights[loss][k] > 0:
                    reg_sum += assemble(Constant(self.reg_weights[loss][k]) * fv)

        return reg_sum

    def to_numpy(self) -> np.ndarray:
        """
        Get the numeric representations of the losses as a vector.
        """
        data_loss = float(self.L_data)
        reg_losses_unweighted = []
        reg_losses_weighted = []

        for loss, rv in self.L_reg.items():
            for k, fv in rv.items():
                if type(fv) == uflForm:
                    fv_num = assemble(fv)
                else:
                    fv_num = fv
                reg_losses_unweighted.append(fv_num)
                reg_losses_weighted.append(self.reg_weights[loss][k] * fv_num)

        reg_loss = sum(reg_losses_weighted)
        total_loss = data_loss + reg_loss

        all_losses = np.array([total_loss, data_loss, reg_loss, *reg_losses_weighted, *reg_losses_unweighted])
        assert len(all_losses) == N_ALL_LOSSES

        return all_losses
