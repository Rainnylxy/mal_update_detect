import os
import time

import matplotlib.pyplot as plt
import numpy as np
from fenics import *

try:
    from fenics_adjoint import *
except ModuleNotFoundError:
    # This optional import is only needed if derivatives are being taken.
    pass

from simple_worm.util import f2n
from simple_worm.worm import Worm, grad
from simple_worm.material_parameters import MaterialParameters
from simple_worm.controls import ControlsNumpy

# plt.rcParams.update({
#     'text.usetex': True,
#     'font.family': 'sans-serif',
#     'font.sans-serif': ['Helvetica']})
# plt.rc('text.latex', preamble=r'\usepackage{amsmath}')

show_plots = True
save_plots = False

T = 0.5


def check_gamma_residuals():
    Ns = [10 * (2**i) for i in range(3, 4)]
    print(Ns)
    dts = [1 / (2**i) for i in range(3, 6)]
    print(dts)
    # exit()

    MP = MaterialParameters(K=2)

    fig, axes = plt.subplots(2, 2, figsize=(14, 12))
    fig_scat, axes_scat = plt.subplots(2, figsize=(14, 12))
    fig_res, axes_res = plt.subplots(3, figsize=(14, 12))
    ax_init = axes[0, 0]
    ax_init.set_title('At initialisation')
    ax_init.set_xlabel('body coordinate')
    ax_final_model = axes[1, 0]
    ax_final_model.set_title('After solve: model')
    ax_final_model.set_xlabel('body coordinate')
    ax_final_recalc = axes[1, 1]
    ax_final_recalc.set_title('After solve: recalculated')
    ax_final_recalc.set_xlabel('body coordinate')
    ax_res = axes[0, 1]
    ax_res.set_title('$\gamma$ residuals over time')
    ax_res.set_xlabel('time')
    ax_scat_N = axes_scat[0]
    ax_scat_N.set_title('Effect of N on final residual')
    ax_scat_N.set_xlabel('N')
    ax_scat_dt = axes_scat[1]
    ax_scat_dt.set_title('Effect of dt on final residual')
    ax_scat_dt.set_xlabel('dt')
    ax_res_t = axes_res[0]
    ax_res_t.set_title('$\gamma$ residuals over time')
    ax_res_t.set_xlabel('time')
    ax_res_diff = axes_res[1]
    ax_res_diff.set_title('$res(\gamma(t))-res(\gamma(t-1))$')
    ax_res_diff.set_xlabel('time')
    ax_res_cum = axes_res[2]
    ax_res_cum.set_title('cumulative $res(\gamma)$')
    ax_res_cum.set_xlabel('time')

    residuals = np.zeros((len(Ns), len(dts)))

    for i, N in enumerate(Ns):
        u = np.linspace(start=0, stop=1, num=N - 1)

        for j, dt in enumerate(dts):
            label = f'N={N}, dt={dt}'
            print(f'Solving for {label}...')

            gamma_pref = np.linspace(start=-1, stop=1, num=N - 1) * 5
            # gamma_pref = np.ones(N - 1) * 5
            C = ControlsNumpy(
                # alpha=np.ones(N) * 5,
                alpha=np.zeros(N),
                # beta=np.linspace(start=-1, stop=1, num=N) * 5,
                beta=np.ones(N) * 5,
                # gamma=np.ones(N - 1) * 5,
                gamma=gamma_pref,
            )

            worm = Worm(N, dt)
            worm.initialise(MP=MP)

            if i == len(Ns) - 1 and j == len(dts) - 1:
                ax_init.plot(u, f2n(project(worm.F.gamma, worm.Q)), label='$\gamma$')
                ax_init.plot(u, gamma_pref, label='$\gamma^0$')

            gamma_res = []
            while worm.t < T:
                print(f't={worm.t:.6f}')
                F = worm.update_solution(C.to_fenics(worm))
                mu = sqrt(dot(grad(F.x), grad(F.x)))
                # res = assemble((F.gamma_expr - dot(grad(F.e1), F.e2)) / mu * dx)
                res = assemble(((F.gamma_expr - dot(grad(F.e1), F.e2)) / mu)**2 * dx)
                gamma_res.append(res)
            gamma_res = np.array(gamma_res)
            residuals[i, j] = gamma_res[-1]

            # Recalculate gamma from e1, e2
            x0 = project(worm.F.x, worm.V3)
            mu0 = sqrt(dot(grad(x0), grad(x0)))
            gamma = TrialFunction(worm.Q)
            v = TestFunction(worm.Q)
            F_gamma0 = (gamma - dot(grad(worm.F.e1), worm.F.e2)) / mu0 * v * dx
            a_gamma0, L_gamma0 = lhs(F_gamma0), rhs(F_gamma0)
            gamma0 = Function(worm.Q)
            solve(a_gamma0 == L_gamma0, gamma0)

            ax_final_model.plot(u, f2n(project(F.gamma_expr, worm.Q)), label=label)
            ax_final_recalc.plot(u, f2n(project(gamma0, worm.Q)), label=label)

            ts = np.linspace(start=0, stop=T, num=len(gamma_res))
            ax_res.plot(ts, gamma_res, label=label)

            ax_res_t.plot(ts, gamma_res, label=label)

            gamma_res_diff = gamma_res[1:] - gamma_res[:-1]
            gamma_res_diff = np.r_[gamma_res[0], gamma_res_diff]
            ax_res_diff.plot(ts, gamma_res_diff, label=label)

            gamma_res_cum = np.cumsum(gamma_res)
            ax_res_cum.plot(ts, gamma_res_cum, label=label)

    print(residuals)

    cmap = plt.get_cmap('rainbow')

    cs = np.linspace(0, 1, num=len(dts))
    for i, dt in enumerate(dts):
        c = cmap(np.ones(len(Ns)) * cs[i])
        ax_scat_N.scatter(x=Ns, y=residuals[:, i], c=c, alpha=0.8, label=f'dt={dt:.4E}')

    cs = np.linspace(0, 1, num=len(Ns))
    for i, N in enumerate(Ns):
        c = cmap(np.ones(len(dts)) * cs[i])
        ax_scat_dt.scatter(x=dts, y=residuals[i], c=c, alpha=0.8, label=f'N={N}')

    ax_init.legend()
    ax_res.legend()
    ax_final_model.legend()
    ax_final_recalc.legend()

    ax_scat_N.set_xscale('log')
    ax_scat_dt.set_xscale('log')
    ax_scat_N.set_yscale('log')
    ax_scat_dt.set_yscale('log')
    ax_scat_N.legend()
    ax_scat_dt.legend()

    ax_res_t.legend()

    fig.tight_layout()
    fig_scat.tight_layout()
    fig_res.tight_layout()

    if save_plots:
        def savefig(fig_, *args, **kwargs):
            fig_.savefig(*args, **kwargs)
            fig_.canvas.draw_idle()

        save_dir = 'logs/gamma_residual'
        os.makedirs(save_dir, exist_ok=True)
        save_path_prefix = save_dir + '/' + \
                           time.strftime('%Y-%m-%d_%H%M%S') + \
                           f'_T={T:.2f}' \
                           f'_N={Ns[0]}-{Ns[-1]}' \
                           f'_dt={dts[0]:.2E}-{dts[-1]:.2E}'
        savefig(fig_scat, save_path_prefix + '_scatter.svg')
        savefig(fig_res, save_path_prefix + '_residuals.svg')
        savefig(fig, save_path_prefix + '_gammas.svg')

    if show_plots:
        plt.show()


if __name__ == '__main__':
    check_gamma_residuals()
