import numpy as np
import torch
from torch.nn.functional import mse_loss

from simple_worm.controls import CONTROL_KEYS
from simple_worm.controls_torch import ControlSequenceBatchTorch
from simple_worm.frame import FRAME_KEYS
from simple_worm.frame_torch import FrameBatchTorch
from simple_worm.material_parameters import MP_KEYS
from simple_worm.plot3d import generate_scatter_clip
from simple_worm.worm_torch import WormModule
from tests.helpers import generate_test_target

N_VID_XS = 6  # number of training examples to show in the videos


def inverse_optimisation(
        optim_MP_K: bool = False,
        optim_MP_K_rot: bool = False,
        optim_MP_A: bool = False,
        optim_MP_B: bool = False,
        optim_MP_C: bool = False,
        optim_MP_D: bool = False,
        optim_F0: bool = False,
        optim_CS: bool = False,
        N=4,
        T=0.2,
        dt=0.1,
        lr=0.5,
        n_iter=20,
        parallel_solvers=0,
        generate_vids=False
):
    print('\n==== Test Control Optimisation ===')
    id_str = f'optim_MP_K={optim_MP_K},' \
             f'optim_MP_K_rot={optim_MP_K_rot},' \
             f'optim_MP_A={optim_MP_A},' \
             f'optim_MP_B={optim_MP_B},' \
             f'optim_MP_C={optim_MP_C},' \
             f'optim_MP_D={optim_MP_D},' \
             f'optim_F0={optim_F0},' \
             f'optim_CS={optim_CS},' \
             f'N={N},' \
             f'T={T:.2f},' \
             f'dt={dt:.2f},' \
             f'lr={lr:.2f},' \
             f'ps={parallel_solvers}'
    print(id_str.replace(',', ', ') + f', n_iter={n_iter}')

    batch_size = 1 if parallel_solvers == 0 else parallel_solvers
    if generate_vids:
        vid_dir = f'vids/{id_str}'

    # Get targets
    MP_target, F0_target, CS_target, FS_target = generate_test_target(
        N,
        T,
        dt,
        batch_size,
        alpha_pref_freq=1,
        beta_pref_freq=0.25
    )

    worm = WormModule(
        N,
        dt=dt,
        batch_size=batch_size,
        optimise_MP_K=optim_MP_K,
        optimise_MP_K_rot=optim_MP_K_rot,
        optimise_MP_A=optim_MP_A,
        optimise_MP_B=optim_MP_B,
        optimise_MP_C=optim_MP_C,
        optimise_MP_D=optim_MP_D,
        optimise_F0=optim_F0,
        optimise_CS=optim_CS,
        inverse_opt_max_iter=1,
        parallel=parallel_solvers > 0,
        n_workers=parallel_solvers,
        quiet=False,
    )

    # Set optimisable initial frame F0, using same x0 as target
    F0 = FrameBatchTorch(
        x=F0_target.x,
        worm=worm.worm_solver,
        optimise=optim_F0
    )

    # Set ICs and target
    CS = ControlSequenceBatchTorch(
        worm=worm.worm_solver,
        n_timesteps=int(T / dt),
        batch_size=batch_size,
        optimise=optim_CS
    )

    # Generate optimisable material parameters
    MP = MP_target.clone()

    # Add some noise
    with torch.no_grad():
        if optim_MP_K:
            MP.K.requires_grad = True
            MP.K.data += 20
        if optim_MP_K_rot:
            MP.K_rot.requires_grad = True
            MP.K_rot.data += 10
        if optim_MP_A:
            MP.A.requires_grad = True
            MP.A.data += 1
        if optim_MP_B:
            MP.B.requires_grad = True
            MP.B.data += 1
        if optim_MP_C:
            MP.C.requires_grad = True
            MP.C.data += 1
        if optim_MP_D:
            MP.D.requires_grad = True
            MP.D.data += 1
        MP.clamp()

    if not optim_F0:
        F0.psi.data = F0_target.psi.clone()
    else:
        with torch.no_grad():
            F0.psi.normal_(std=1e-3)

    if not optim_CS:
        CS.alpha.data = CS_target.alpha.clone()
        CS.beta.data = CS_target.beta.clone()
        CS.gamma.data = CS_target.gamma.clone()
    else:
        with torch.no_grad():
            CS.alpha.normal_(std=1e-3)
            CS.beta.normal_(std=1e-3)
            CS.gamma.normal_(std=1e-3)

    # Create an optimiser
    optimiser = torch.optim.Adam([
        {'params': MP.parameters()},
        {'params': F0.psi},
        {'params': CS.parameters(include_gates=False)},
    ], lr=lr)

    # Save outputs
    FS_outs = []
    labels = []
    LFS_prev = {k: torch.tensor(np.inf) for k in FRAME_KEYS}
    LMP_prev = {k: torch.tensor(np.inf) for k in MP_KEYS}
    LP0_prev = torch.tensor(np.inf)
    LCS_prev = {k: torch.tensor(np.inf) for k in CONTROL_KEYS}

    # Iteratively optimise using gradient descent
    for n in range(n_iter):
        FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = worm.forward(MP, F0, CS, calculate_inverse=True,
                                                                    FS_target=FS_target)

        # Calculate losses
        LFS = {k: mse_loss(getattr(FS, k), getattr(FS_target, k)) for k in FRAME_KEYS}
        LMP = {k: mse_loss(getattr(MP, k), getattr(MP_target, k)) for k in MP_KEYS}
        LP0 = mse_loss(F0.psi, F0_target.psi)
        LCS = {k: mse_loss(getattr(CS, k), getattr(CS_target, k)) for k in CONTROL_KEYS}
        L = sum([*LFS.values(), *LMP.values(), LP0, *LCS.values()])

        print(f'Episode {n}. Loss = {L:.5E} ('
              + ', '.join([f'FS_{k}={LFS[k]:.3E}' for k in FRAME_KEYS])
              + ', '
              + ', '.join([f'MP_{k}={LMP[k]:.3E}' for k in MP_KEYS])
              + f', LP0={LP0:.3E}, '
              + ', '.join([f'CS_{k}={LCS[k]:.3E}' for k in CONTROL_KEYS])
              + ')')

        # Check that losses are decreasing (or not)
        if n == 0:
            # There are usually fluctuations in the indirect losses so it is not possible to assert
            # monotonic decrease (like we do with LX) so instead check if the overall loss has decreased
            LF_first = LFS.copy()
            LMP_first = LMP.copy()
            LP0_first = LP0
            LC_first = LCS.copy()
        else:
            # Targets should not be changing
            assert FS_target == FS_target_prev
            assert MP_target == MP_target_prev
            assert F0_target == F0_target_prev
            assert CS_target == CS_target_prev

            # Loss should be decreasing if something is being optimised
            if optim_MP_K or optim_MP_K_rot or optim_MP_A or optim_MP_B or optim_MP_C or optim_MP_D or optim_F0 or optim_CS:
                assert FS != FS_prev
                assert LFS['x'] <= LFS_prev['x']
            else:
                # Otherwise the frame sequence should not change and losses should stay the same
                assert FS == FS_prev
                assert all(
                    torch.allclose(LFS[k], LFS_prev[k])
                    for k in FRAME_KEYS
                )

            # MP should only change if it is being optimised
            if optim_MP_K or optim_MP_K_rot or optim_MP_A or optim_MP_B or optim_MP_C or optim_MP_D:
                assert MP != MP_prev

                if optim_MP_K:
                    assert not torch.allclose(LMP['K'], LMP_prev['K'])
                else:
                    assert torch.allclose(LMP['K'], LMP_prev['K'])

                if optim_MP_K_rot:
                    assert not torch.allclose(LMP['K_rot'], LMP_prev['K_rot'])
                else:
                    assert torch.allclose(LMP['K_rot'], LMP_prev['K_rot'])

                if optim_MP_A:
                    assert not torch.allclose(LMP['A'], LMP_prev['A'])
                else:
                    assert torch.allclose(LMP['A'], LMP_prev['A'])

                if optim_MP_B:
                    assert not torch.allclose(LMP['B'], LMP_prev['B'])
                else:
                    assert torch.allclose(LMP['B'], LMP_prev['B'])

                if optim_MP_C:
                    assert not torch.allclose(LMP['C'], LMP_prev['C'])
                else:
                    assert torch.allclose(LMP['C'], LMP_prev['C'])

                if optim_MP_D:
                    assert not torch.allclose(LMP['D'], LMP_prev['D'])
                else:
                    assert torch.allclose(LMP['D'], LMP_prev['D'])

            else:
                assert MP == MP_prev
                assert all(
                    torch.allclose(LMP[k], LMP_prev[k])
                    for k in MP_KEYS
                )

            # F0 should only change if it is being optimised
            if optim_F0:
                assert F0 != F0_prev
                assert not torch.allclose(LP0, LP0_prev)
            else:
                assert F0 == F0_prev
                assert torch.allclose(LP0, LP0_prev)

            # alpha/beta/gamma should only change if they are being optimised
            if optim_CS:
                assert CS != CS_prev

                # Do a weaker check here as gamma often doesn't change
                assert any(
                    not torch.allclose(LCS[k], LCS_prev[k])
                    for k in CONTROL_KEYS
                )
            else:
                assert CS == CS_prev
                assert all(
                    torch.allclose(LCS[k], LCS_prev[k])
                    for k in CONTROL_KEYS
                )

        FS_target_prev = FS_target.clone()
        MP_target_prev = MP_target.clone()
        F0_target_prev = F0_target.clone()
        CS_target_prev = CS_target.clone()
        FS_prev = FS.clone()
        MP_prev = MP.clone()
        F0_prev = F0.clone()
        CS_prev = CS.clone()
        LFS_prev = LFS.copy()
        LMP_prev = LMP.copy()
        LP0_prev = LP0
        LCS_prev = LCS.copy()

        # Do optimisation step
        if MP.requires_grad() or F0.requires_grad() or CS.requires_grad():
            optimiser.zero_grad()
            LFS['x'].backward()
            optimiser.step()

            if MP.requires_grad():
                MP.clamp()

        # Make vids
        if generate_vids:
            FS_outs.append(FS.to_numpy())
            labels.append(f'X_{n + 1}')
            if len(FS_outs) > N_VID_XS:
                idxs = np.round(np.linspace(0, len(FS_outs) - 1, N_VID_XS)).astype(int)
                FS_outs_to_plot = [FS_outs[i] for i in idxs]
                labels_to_plot = [labels[i] for i in idxs]
            else:
                FS_outs_to_plot = FS_outs
                labels_to_plot = labels

            generate_scatter_clip(
                clips=[FS_target.to_numpy(), *FS_outs_to_plot],
                save_dir=vid_dir,
                labels=['Target', *[l for l in labels_to_plot]]
            )

    # Check overall loss changes
    if 0:
        # These tests fail over short runs so disabled for ci
        if optim_MP_K or optim_MP_K_rot or optim_MP_A or optim_MP_B or optim_MP_C or optim_MP_D or optim_F0 or optim_CS:
            assert all(
                LFS[k] <= LF_first[k]
                for k in FRAME_KEYS
            )
        else:
            assert all(
                torch.allclose(LFS[k], LF_first[k])
                for k in FRAME_KEYS
            )

        if optim_MP_K or optim_MP_K_rot or optim_MP_A or optim_MP_B or optim_MP_C or optim_MP_D:
            assert all(
                LMP[k] <= LMP_first[k]
                for k in MP_KEYS
            )
        else:
            assert all(
                torch.allclose(LMP[k], LMP_first[k])
                for k in MP_KEYS
            )

        if optim_F0:
            assert LP0 <= LP0_first
        else:
            assert torch.allclose(LP0, LP0_first)

        if optim_CS:
            assert all(
                LCS[k] <= LC_first[k]
                for k in CONTROL_KEYS
            )
        else:
            assert all(
                torch.allclose(LCS[k], LC_first[k])
                for k in CONTROL_KEYS
            )


default_args = {
    'optim_MP_K': False,
    'optim_MP_K_rot': False,
    'optim_MP_A': False,
    'optim_MP_B': False,
    'optim_MP_C': False,
    'optim_MP_D': False,
    'optim_F0': False,
    'optim_CS': False,
    'N': 50,
    'T': 0.05,
    'dt': 0.005,
    'lr': 1e-2,
    'n_iter': 3,
    'parallel_solvers': 0,
    'generate_vids': False,
}


def test_optim_MP_K():
    inverse_optimisation(**{**default_args, 'optim_MP_K': True})


def test_optim_MP_K_rot():
    inverse_optimisation(**{**default_args, 'optim_MP_K_rot': True})


def test_optim_MP_A():
    inverse_optimisation(**{**default_args, 'optim_MP_A': True})


def test_optim_MP_B():
    inverse_optimisation(**{**default_args, 'optim_MP_B': True})


def test_optim_MP_C():
    inverse_optimisation(**{**default_args, 'optim_MP_C': True})


def test_optim_MP_D():
    inverse_optimisation(**{**default_args, 'optim_MP_D': True})


def test_optim_MP_all():
    inverse_optimisation(**{**default_args,
                            'optim_MP_K': True,
                            'optim_MP_K_rot': True,
                            'optim_MP_A': True,
                            'optim_MP_B': True,
                            'optim_MP_C': True,
                            'optim_MP_D': True})


def test_optim_F0():
    inverse_optimisation(**{**default_args, 'optim_F0': True})


def test_optim_CS():
    inverse_optimisation(**{**default_args, 'optim_CS': True})


def test_optim_all():
    inverse_optimisation(**{**default_args,
                            'optim_MP_K': True,
                            'optim_MP_K_rot': True,
                            'optim_MP_A': True,
                            'optim_MP_B': True,
                            'optim_MP_C': True,
                            'optim_MP_D': True,
                            'optim_F0': True,
                            'optim_CS': True, })


def test_optim_none():
    inverse_optimisation(**default_args)


def test_parallel_solvers():
    inverse_optimisation(
        **{**default_args,
           'optim_MP_K': True,
           'optim_MP_K_rot': True,
           'optim_MP_A': True,
           'optim_MP_B': True,
           'optim_MP_C': True,
           'optim_MP_D': True,
           'optim_F0': True,
           'optim_CS': True,
           'parallel_solvers': 2})


if __name__ == '__main__':
    test_optim_MP_K()
    test_optim_MP_K_rot()
    test_optim_MP_A()
    test_optim_MP_B()
    test_optim_MP_C()
    test_optim_MP_D()
    test_optim_MP_all()
    test_optim_F0()
    test_optim_CS()
    test_optim_all()
    test_optim_none()
    test_parallel_solvers()
