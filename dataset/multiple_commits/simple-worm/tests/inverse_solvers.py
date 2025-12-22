import sys

import pytest
import torch

from simple_worm.controls import CONTROL_KEYS
from simple_worm.controls_torch import ControlSequenceBatchTorch
from simple_worm.worm_inv import INVERSE_SOLVER_LIBRARY_SCIPY, INVERSE_SOLVER_LIBRARY_IPOPT
from simple_worm.worm_torch import WormModule

sys.path.append('.')
from tests.helpers import generate_test_target

N = 100
T = 0.05
dt = 0.01

MP = None
F0 = None
CS = None
MP_target = None
F0_target = None
CS_target = None
FS_target = None

TEST_METHODS = {
    INVERSE_SOLVER_LIBRARY_SCIPY: ['L-BFGS-B'],
    # INVERSE_SOLVER_LIBRARY_IPOPT: ['ma27', 'ma57', 'ma77', 'ma86', 'ma97', 'pardiso', 'mumps']
    INVERSE_SOLVER_LIBRARY_IPOPT: ['mumps']
}

default_args = dict(
    N=N,
    dt=dt,
    batch_size=1,
    # optimise_MP_K=True,
    # optimise_MP_K_rot=True,
    # optimise_MP_A=True,
    # optimise_MP_B=True,
    # optimise_MP_C=True,
    # optimise_MP_D=True,
    optimise_F0=True,
    optimise_CS=True,
    inverse_opt_max_iter=5,
    mkl_threads=1,
    quiet=False,
)


def _init(worm: WormModule):
    global MP, F0, CS
    _init_targets()

    MP = MP_target.clone()
    F0 = F0_target.clone()

    CS = ControlSequenceBatchTorch(
        worm=worm.worm_solver,
        n_timesteps=int(T / dt),
        batch_size=1,
        optimise=True
    )

    # Add some noise
    with torch.no_grad():
        # for k in MP_KEYS:
        #     p = getattr(MP, k)
        #     setattr(p, 'requires_grad', True)
        #     setattr(p, 'data', (p.data + 0.01) * 2)
        # MP.clamp()
        F0.psi.normal_(std=1e-3)
        CS.alpha.normal_(std=0.1)
        CS.beta.normal_(std=0.1)
        CS.gamma.normal_(std=0.1)

    # Set dtype
    for k in CONTROL_KEYS:
        CS.controls[k] = CS.controls[k].to(torch.float64)


def _init_targets():
    global MP_target, F0_target, CS_target, FS_target
    if MP_target is None:
        MP_target, F0_target, CS_target, FS_target = generate_test_target(
            N,
            T,
            dt,
            batch_size=1,
            alpha_pref_freq=1,
            beta_pref_freq=0.25
        )


def test_unrecognised_library():
    with pytest.raises(AssertionError):
        WormModule(inverse_opt_library='somerubbish', **default_args)


def test_unrecognised_method():
    with pytest.raises(AssertionError):
        WormModule(inverse_opt_method='somerubbish', **default_args)


def test_methods():
    for library, methods in TEST_METHODS.items():
        for method in methods:
            print(f'\n==== Test Library={library} Method={method} ===')
            worm = WormModule(inverse_opt_library=library, inverse_opt_method=method, **default_args)
            _init(worm)
            FS, L, MP_opt, F0_opt, CS_opt, FS_opt, L_opt = worm.forward(
                MP, F0, CS, calculate_inverse=True, FS_target=FS_target
            )
            assert 0 < L_opt.total < L.total * 1.1
            assert FS != FS_opt
            assert F0 != F0_opt
            assert CS != CS_opt


if __name__ == '__main__':
    test_unrecognised_library()
    test_unrecognised_method()
    test_methods()
