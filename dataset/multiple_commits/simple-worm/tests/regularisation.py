from simple_worm.trainer import Trainer


def train_inv_reg(
        optim_MP_K: bool = False,
        optim_MP_K_rot: bool = False,
        optim_MP_A: bool = False,
        optim_MP_B: bool = False,
        optim_MP_C: bool = False,
        optim_MP_D: bool = False,
        optim_F0=False,
        optim_CS=False,
        reg_weights={},
        N=4,
        T=0.2,
        dt=0.1,
        lr=0.5,
        n_steps=1,
        inverse_opt_max_iter=1,
        save_videos=False,
        save_plots=False

):
    print('\n==== Test Regularisation ===')
    print(f'reg_weights={reg_weights}\n')

    trainer = Trainer(
        N=N,
        T=T,
        dt=dt,
        optim_MP_K=optim_MP_K,
        optim_MP_K_rot=optim_MP_K_rot,
        optim_MP_A=optim_MP_A,
        optim_MP_B=optim_MP_B,
        optim_MP_C=optim_MP_C,
        optim_MP_D=optim_MP_D,
        optim_F0=optim_F0,
        optim_CS=optim_CS,
        target_params={'alpha_pref_freq': 1, 'beta_pref_freq': 0.5},
        lr=lr,
        reg_weights=reg_weights,
        inverse_opt_max_iter=inverse_opt_max_iter,
        save_videos=save_videos,
        save_plots=save_plots,
    )
    trainer.train(n_steps)
    print('done')


default_args = {
    'optim_MP_K': False,
    'optim_MP_K_rot': False,
    'optim_MP_A': False,
    'optim_MP_B': False,
    'optim_MP_C': False,
    'optim_MP_D': False,
    'optim_F0': True,
    'optim_CS': True,
    'reg_weights': {},
    'N': 20,
    'dt': 0.01,
    'T': 0.03,
    'lr': 1e-2,
    'n_steps': 2,
    'inverse_opt_max_iter': 2,
    'save_videos': False,
    'save_plots': False,
}


def test_inv_reg_L2():
    rw = {
        'L2': {
            'alpha': 1e-7,
            'beta': 1e-7,
            'gamma': 1e-4,
        }
    }
    train_inv_reg(**{**default_args, 'reg_weights': rw})


def test_inv_reg_grad_t():
    rw = {
        'grad_t': {
            'alpha': 1e-8,
            'beta': 1e-8,
            'gamma': 1e-7,
        },
    }
    train_inv_reg(**{**default_args, 'reg_weights': rw})


def test_inv_reg_grad_x():
    rw = {
        'grad_x': {
            'psi0': 1e-8,
            'alpha': 1e-8,
            'beta': 1e-8,
        }
    }
    train_inv_reg(**{**default_args, 'reg_weights': rw})


def test_inv_reg_all():
    rw = {
        'L2': {
            'alpha': 1e-6,
            'beta': 1e-6,
            'gamma': 1e-5,
        },
        'grad_t': {
            'alpha': 1e-6,
            'beta': 1e-6,
            'gamma': 1e-6,
        },
        'grad_x': {
            'psi0': 1e-7,
            'alpha': 1e-7,
            'beta': 1e-7,
        }
    }
    train_inv_reg(**{**default_args, 'reg_weights': rw})


if __name__ == '__main__':
    test_inv_reg_L2()
    test_inv_reg_grad_t()
    test_inv_reg_grad_x()
    test_inv_reg_all()
