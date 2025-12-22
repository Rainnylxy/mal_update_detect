import sys

import torch

from simple_worm.controls_torch import ControlSequenceBatchTorch
from simple_worm.worm_torch import WormModule

sys.path.append('.')
from tests.helpers import generate_test_target

N = 50
T = 0.5
dt = 0.01
n_iter = 5
max_alpha_beta = 0.01
max_gamma = 0.01
inverse_opt_max_iter = 4


def test_controls_bounds():
    print('\n==== Test Inverse Bounds ===')
    print(f'N={N}, T={T:.2f}, dt={dt:.2f}, n_iter={n_iter}')

    # Get targets
    MP_target, F0_target, CS_target, FS_target = generate_test_target(
        N,
        T,
        dt,
        batch_size=1,
        alpha_pref_freq=1,
        beta_pref_freq=0.25
    )

    worm = WormModule(
        N,
        dt=dt,
        batch_size=1,
        optimise_F0=False,
        optimise_CS=True,
        max_alpha_beta=max_alpha_beta,
        max_gamma=max_gamma,
        inverse_opt_max_iter=inverse_opt_max_iter,
        quiet=False,
    )

    # Not optimising MP or F0 so just clone from target
    MP = MP_target.clone()
    F0 = F0_target.clone()

    # Set optimisable controls
    CS = ControlSequenceBatchTorch(
        worm=worm.worm_solver,
        n_timesteps=int(T / dt),
        batch_size=1,
        optimise=True
    )
    with torch.no_grad():
        CS.alpha.normal_(std=1)
        CS.beta.normal_(std=1)
        CS.gamma.normal_(std=1)

    # Iteratively optimise using gradient descent
    for n in range(n_iter):
        FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = worm.forward(MP, F0, CS, calculate_inverse=True,
                                                                    FS_target=FS_target)

        # Check bounds aren't exceeded
        assert torch.all(CS_opt.controls['alpha'] >= -max_alpha_beta)
        assert torch.all(CS_opt.controls['alpha'] <= max_alpha_beta)
        assert torch.all(CS_opt.controls['beta'] >= -max_alpha_beta)
        assert torch.all(CS_opt.controls['beta'] <= max_alpha_beta)
        assert torch.all(CS_opt.controls['gamma'] >= -max_gamma)
        assert torch.all(CS_opt.controls['gamma'] <= max_gamma)

        print(f'Episode {n}. Loss = {L.total.sum():.5E}.')

        # Update controls to optimals
        CS.controls = CS_opt.controls


if __name__ == '__main__':
    test_controls_bounds()
